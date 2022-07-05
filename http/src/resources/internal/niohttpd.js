const WS_ADMIN_GET_STATS_RESPONSE                = 0;
const WS_ADMIN_PING                              = 1;
const WS_ADMIN_PONG                              = 1;
const WS_ADMIN_GET_STATS_AFTER_TIMESTAMP_REQUEST = 2;
const WS_ADMIN_GET_MOST_RECENT_REQUESTS          = 3;
const WS_ADMIN_GET_MOST_RECENT_RESPONSE          = 3;

const METHOD_GET     = 0;
const METHOD_POST    = 1;
const METHOD_PUT     = 2;
const METHOD_DELETE  = 3;
const METHOD_HEAD    = 4;
const METHOD_OPTIONS = 5;
const METHOD_CONNECT = 6;
const METHOD_PATCH   = 7;
const METHOD_TRACE   = 8;

const VERSION_10      = 1;
const VERSION_11      = 2;
const VERSION_20      = 3;
const VERSION_UNKNOWN = 0;

const MAX_LOG_STR_LEN = 128;

var last_scroll = 0;
var mr_micros = 0;
var mr_timestamp = 0;
var first_entry = 0;
var color_alternate = 0;
var sock_connected = true;
var sock;
var pause = false;

function do_pause() {
	if(pause) {
		location.reload();
	} else {
		pause = true;
		document.getElementById('playpause').src = "?play";
	}
}

function to_u64(buffer, offset) {
	var num = BigInteger.ZERO;
	var itt = 0;
	for(var i=7+offset; i>=offset; i--) {
		num = num.add(
			new BigInteger(
				String(buffer[i]),
				10
			).shiftLeft(
				new BigInteger(
					String(itt),
					10
				).multiply(
					new BigInteger("8", 10)
				)       
			)       
		);      
		itt++;
	}       

	return num;
}

function to_u16(buffer, offset) {
	var num = BigInteger.ZERO;
	var itt = 0;
	for(var i=1+offset; i>=offset; i--) {
		num = num.add(
			new BigInteger(
				String(buffer[i]),
				10
			).shiftLeft(
				new BigInteger(
					String(itt),
					10
				).multiply(
					new BigInteger("8", 10)
				)
			)
		);
		itt++;
	}

	return num;
}

function u64_tobin(bint, buffer, offset) {
	for(var i=0; i<8; i++) {
		buffer[i+offset] = 0;
	}

	var str16 = bint.toString(16);
	var len = str16.length;
	if(len % 2 != 0) {
		str16 = '0' + str16;
		len++;
	}
	var itt = 7+offset;
	for(var i=len-2; i>=0; i-=2) {
		var hex = str16.substring(i, i+2);
		var num = parseInt(hex, 16);
		buffer[itt] = num;
		itt--;
	}
}

function format_time(time) {
	var diff = Math.round(time / 1000);
        if(diff <= 3) {
		diff = 'NOW!';
	} else if(diff < 60) {
		diff = diff + ' secs';
	} else if(diff < 3600) {
		diff = Math.round(diff / 60);
		if(diff == 1)
			diff = diff + ' min';
		else
			diff = diff + ' mins';
	} else if(diff < 86400) {
		diff = Math.round(diff / 3600);
		if(diff == 1)
			diff = diff + ' hour';
		else
			diff = diff + ' hours';
	} else {
		diff = Math.round(diff / 86400);
		if(diff == 1)
			diff = diff + ' days';
		else
			diff = diff + ' days';
	}

	return diff;
}

function update_td_time(td, now) {
	var timestamp = td.timestamp;
	var diff = format_time(now - timestamp);
	td.innerHTML = '';
	if (Math.round((now - timestamp) / 1000) > 3) {
		td.appendChild(document.createTextNode(diff + ' ago.'));
	}
	else {
		td.appendChild(document.createTextNode(diff));
	}
}

function update_timestamps(now) {
	console.log("update timestamps " + now);
	var timestamps = document.getElementsByClassName("timestamp");
	console.log("timestamps len = " + timestamps.length);
	for(var i=0; i<timestamps.length; i++) {
		var td = timestamps[i];
		update_td_time(td, now);
	}
}

function add_tr(
	requests,
	dropped_log,
	conns,
	connects,
	disconnects,
	connect_timeouts,
	read_timeouts,
	timestamp,
	prev_timestamp,
	startup_time,
	table,
	color_alternate,
	first,
	server_time,
	lat_sum_micros,
) {
	if(timestamp > mr_timestamp) {
		mr_timestamp = timestamp;
	}

	var tr = document.createElement('tr');
	if (first_entry == 0) {
		first_entry = tr;
	}

	var fmt = new Intl.NumberFormat('en-US');

        var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd timestamp'; } else { td.className = 'table_even timestamp'; }
	td.timestamp = timestamp;
	td.title = String(new Date(timestamp / 1));
	update_td_time(td, server_time);
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(fmt.format(requests)));
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(fmt.format(dropped_log)));
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(fmt.format(conns)));
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(fmt.format(connects)));
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(fmt.format(disconnects)));
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(fmt.format(connect_timeouts)));
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(fmt.format(read_timeouts)));
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	var duration = Math.round((timestamp - prev_timestamp) / 1000);
	td.appendChild(document.createTextNode(duration + ' secs'));
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	var uptime = format_time(timestamp - startup_time);
	td.appendChild(document.createTextNode(uptime));
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	var qps = requests;
	if(duration >= 1) {
		qps = requests / duration;
	}
	td.appendChild(document.createTextNode(fmt.format(qps)));
	tr.appendChild(td);

        var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	var avg_lat = 0;
	if(requests > 0) {
		avg_lat = lat_sum_micros / requests;
	}
	td.appendChild(document.createTextNode(fmt.format(avg_lat) + ' (\u03BCs)'));
	tr.appendChild(td);

	if (first) {
		table.insertBefore(tr, first_entry);
		first_entry = tr;
	} else {
		table.appendChild(tr);
	}
}

function process_pong(buffer) {
	var table = document.getElementById('stats_table');

	// not on stats page.
	if(table == null) {
		return;
	}

	var server_time = to_u64(buffer, 1);
	update_timestamps(server_time);
        var count = to_u64(buffer, 9);
	console.log('count='+count);

	for(var i=count-1; i>=0; i--) {
		var offset = 17 + i * 88;
		console.log('offset='+offset + ",i=" + i);
		var requests = to_u64(buffer, offset); offset += 8;
		var dropped_log = to_u64(buffer, offset); offset += 8;
		var conns = to_u64(buffer, offset); offset += 8;
		var connects = to_u64(buffer, offset); offset += 8;
		var disconnects = to_u64(buffer, offset); offset += 8;
		var connect_timeouts = to_u64(buffer, offset); offset += 8;
		var read_timeouts = to_u64(buffer, offset); offset += 8;
		var timestamp = to_u64(buffer, offset); offset += 8;
		var prev_timestamp = to_u64(buffer, offset); offset += 8;
		var startup_time = to_u64(buffer, offset); offset += 8;
		var lat_sum_micros = to_u64(buffer, offset); offset += 8;

		if(timestamp > mr_timestamp) {
			mr_timestamp = timestamp;
			color_alternate += 1;

			add_tr(
				requests, dropped_log, conns, connects,
				disconnects, connect_timeouts, read_timeouts,
				timestamp, prev_timestamp, startup_time, table, color_alternate, true, server_time,
				lat_sum_micros
			);
		}

	}
}

function process_ws_admin_get_stats_response(buffer) {
	var server_time = to_u64(buffer, 1);
	var count = to_u64(buffer, 9);
	console.log('count='+count);
	var offset = 17;

	var table = document.getElementById('stats_table');
	var table_created = false;

	if (table == null) {
		table_created = true;
		table = document.createElement('table');
		table.id = 'stats_table';
		var tr = document.createElement('tr');

                var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Time'));
		tr.appendChild(td);

        	var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Requests'));
		tr.appendChild(td);

        	var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Drop (log)'));
		tr.appendChild(td);

        	var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Connections'));
		tr.appendChild(td);

        	var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('New Connections'));
		tr.appendChild(td);

        	var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Disconnects'));
		tr.appendChild(td);

        	var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('CTimeouts'));
		tr.appendChild(td);

        	var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('RTimeouts'));
		tr.appendChild(td);

        	var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Duration'));
		tr.appendChild(td);

        	var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Uptime'));
		tr.appendChild(td);

		var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('QPS'));
		tr.appendChild(td);

		var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('AVG Latency'));
		tr.appendChild(td);

		table.appendChild(tr);
	}

	var last_timestamp = 0;
	for (var i=0; i<count; i++) {
		var requests = to_u64(buffer, offset); offset += 8;
		var dropped_log = to_u64(buffer, offset); offset += 8;
		var conns = to_u64(buffer, offset); offset += 8;
		var connects = to_u64(buffer, offset); offset += 8;
		var disconnects = to_u64(buffer, offset); offset += 8;
		var connect_timeouts = to_u64(buffer, offset); offset += 8;
		var read_timeouts = to_u64(buffer, offset); offset += 8;
		var timestamp = to_u64(buffer, offset); offset += 8;
		var prev_timestamp = to_u64(buffer, offset); offset += 8;
		var startup_time = to_u64(buffer, offset); offset += 8;
		var lat_sum_micros = to_u64(buffer, offset); offset += 8;

		last_timestamp = timestamp;
		console.log('record { requests: ' + requests + ', timestamp: ' + timestamp);

		add_tr(
			requests, dropped_log, conns, connects,
			disconnects, connect_timeouts, read_timeouts,
			timestamp, prev_timestamp, startup_time, table, i, false, server_time, lat_sum_micros
		);
	}

	if(table_created) {
		var tr = document.createElement('tr');
        	if (first_entry == 0) {
			first_entry = tr;
		}

		tr.id = 'last_tr';
		var td = document.createElement('td');
		td.colSpan = 12;
		td.className = 'table_heading centered_cell';
		var text = document.createTextNode('View Older Data');
		var link = document.createElement('a');
		link.id = 'load_more';
		link.last = last_timestamp;
		link.onclick = function(evt) {
                	const buffer = new ArrayBuffer(17);
			const view = new Uint8Array(buffer);
			for(var i=0; i<16; i++) {
				view[i] = 0;
			}
			view[0] = 2;
			u64_tobin(this.last, view, 1);
			view[16] = 30;
			sock.send(buffer);

			return false;
		};
		link.className = 'load_more';
		link.appendChild(text);
		td.appendChild(link);
		tr.appendChild(td);
		table.appendChild(tr);

		var statsdiv = document.getElementById('statsdiv');
        	statsdiv.innerHTML = '';
		statsdiv.appendChild(table);
	}
	else {
		document.getElementById('load_more').last = last_timestamp;
		var last_tr = document.getElementById('last_tr');
		table.removeChild(last_tr);
		table.appendChild(last_tr);
	}
}

function load_recent_update(sock) {
	setTimeout(
		function() {
			console.log("load_recent_update");
			const buffer = new ArrayBuffer(9);
			var view = new Uint8Array(buffer);
			view[0] = WS_ADMIN_GET_MOST_RECENT_REQUESTS;
			console.log("mr_micros="+mr_micros);

			for(var i=1; i<9; i++) view[i] = 0;
			var str16 = mr_micros.toString(16);
			var len = str16.length;
			if(len % 2 != 0) {
				str16 = '0' + str16;
				len++;
			}

			var itt = 8;
			for(var i=len-2; i>=0; i-=2) {
				var hex = str16.substring(i, i+2);
				var num = parseInt(hex, 16);
				view[itt] = num;
				itt--;
			}

			sock.send(buffer);
			if (sock_connected) {
				load_recent_update(sock);
			} else {
				return;
			}
		},
		3000
	);
}

function ping(sock) {
	setTimeout(
		function() {
			console.log("ping");
			const buffer = new ArrayBuffer(1);
			const view = new Uint8Array(buffer);
			view[0] = WS_ADMIN_PING; 
			sock.send(buffer);
			if (sock_connected) {
				ping(sock);
			} else {
				return;
			}
		},
		3000
	);
}

function text_decode(buffer, offset, len) {
	var actual_len = 0;
	for(var i=0; i<len; i++) {
		if(buffer[i+offset] == 0) {
			break;
		}
		actual_len += 1;
	}
	const abuffer = new ArrayBuffer(actual_len);
	const view = new Uint8Array(abuffer);

	for(var i=0; i<actual_len; i++) {
		view[i] = buffer[i+offset];
	}

	var text_decoder = new TextDecoder();
	var text = text_decoder.decode(view);

	return text;
}

function truncate_field(f) {
	if(f.length < 35){
		return f;
	}
	return f.substring(0, 35) + "...";
}

function append_span(div, name, value) {
	var span = document.createElement('span');
	span.title = value;
	span.appendChild(document.createTextNode(truncate_field(value)));
	div.appendChild(document.createTextNode(name));
	div.appendChild(span);
}

function get_http_method(http_method) {
	if(http_method == 0) {
		return "GET";
	} else if(http_method == 1) {
		return "POST";
	} else if(http_method == 2) {
		return "PUT";
	} else if(http_method == 3) {
		return "DELETE";
	} else if(http_method == 4) {
		return "HEAD";
	} else if(http_method == 5) {
		return "OPTIONS";
	} else if(http_method == 6) {
		return "CONNECT";
	} else if(http_method == 7) {
		return "PATCH";
	} else {
		return "TRACE";
	}
}

function get_http_version(http_version) {
	if(http_version == 1) {
		return "V1.0";
	} else if(http_version == 2) {
		return "V1.1";
	} else if(http_version == 3) {
		return "V2.0";
	} else {
		return "UNKNOWN";
	}
}

function add_log_request_tr(server_time, http_method, http_version, content_len, end_micros, start_micros, response_code,
	                        uri, query, user_agent, referer, uri_requested, table, color_alternate) {

	if(pause) return;

	if(end_micros > mr_micros) {
		mr_micros = end_micros;
	}
	var tr = document.createElement('tr');

	var fmt = new Intl.NumberFormat('en-US');

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd timestamp'; } else { td.className = 'table_even timestamp'; }
	var timestamp = end_micros / 1000;
	td.timestamp = timestamp;
	td.title = String(new Date(timestamp / 1));
	update_td_time(td, server_time);
	tr.appendChild(td);

	var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(get_http_method(http_method)));
	tr.appendChild(td);

        var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(get_http_version(http_version)));
	tr.appendChild(td);

        var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(content_len));
	tr.appendChild(td);

        var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(String(fmt.format(end_micros - start_micros)) + ' (\u03BCs)'));
	tr.appendChild(td);

        var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	td.appendChild(document.createTextNode(response_code));
	tr.appendChild(td);

        var td = document.createElement('td');
	if (color_alternate % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
	var div = document.createElement('div');
	append_span(div, "URI Returned: ", uri);
	div.appendChild(document.createElement('br'));
	append_span(div, "URI Requested: ", uri_requested);
	div.appendChild(document.createElement('br'));
	append_span(div, "User Agent: ", user_agent);
	div.appendChild(document.createElement('br'));
	append_span(div, "Query: ", query);
	div.appendChild(document.createElement('br'));
	append_span(div, "Referer: ", referer);
	td.appendChild(div);
	tr.appendChild(td);

	if(first_entry == 0) {
		table.appendChild(tr);
	} else {
		table.insertBefore(tr, first_entry);
	}
	first_entry = tr;
}

function process_get_most_recent_requests(buffer) {
	var numOfElements = document.getElementsByTagName('tr').length;

	console.log("process get most recent");
        var server_time = to_u64(buffer, 1);
	update_timestamps(server_time);
	var count = to_u64(buffer, 9);
	console.log('count='+count);
	var offset = 17;

        var server_time = to_u64(buffer, 1);

	var table = document.getElementById('request_table');
	var table_created = false;

	if (table == null) {
		table_created = true;
		table = document.createElement('table');
		table.className = 'request_table';
		table.id = 'request_table';

		var tr = document.createElement('tr');

                var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Time'));
		tr.appendChild(td);

		var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Http Method'));
		tr.appendChild(td);

		var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Http Version'));
		tr.appendChild(td);


                var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Content-Length'));
		tr.appendChild(td);

                var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Latency'));
		tr.appendChild(td);

                var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('Response Code'));
		tr.appendChild(td);

                var td = document.createElement('td');
		td.className = 'table_heading';
		td.appendChild(document.createTextNode('URI, Query, Http Referer, User Agent'));
		tr.appendChild(td);

		table.appendChild(tr);

		var requestsdiv = document.getElementById('requestsdiv');

		requestsdiv.appendChild(table);
	}



	for (var i=0; i<count; i++) {
		var http_method   = buffer[offset]; offset += 1;
		var http_version  = buffer[offset]; offset += 1;
		var content_len   = to_u64(buffer, offset); offset += 8;
		var start_micros  = to_u64(buffer, offset); offset += 8;
		var end_micros    = to_u64(buffer, offset); offset += 8;
		var response_code = to_u16(buffer, offset); offset += 2;

		var uri           = text_decode(buffer, offset, 128); offset += 128;
		var query         = text_decode(buffer, offset, 128); offset += 128;
		var user_agent    = text_decode(buffer, offset, 128); offset += 128;
		var referer       = text_decode(buffer, offset, 128); offset += 128;
		var uri_requested = text_decode(buffer, offset, 128); offset += 128;

		add_log_request_tr(server_time, http_method, http_version, content_len, end_micros, start_micros, response_code,
			uri, query, user_agent, referer, uri_requested, table, color_alternate);
		if(numOfElements > 100 && !pause) {
			table.removeChild(table.lastChild);
		}
		color_alternate += 1;
		
		console.log("Log item = " + http_method + " " + http_version + " " + content_len + " " + uri + " " + query);
	}
}

function init_listener() {
	var loc = window.location, new_uri;
	if (loc.protocol === "https:") {
		new_uri = "wss:";
	} else {
		new_uri = "ws:";
	}
	new_uri += "//" + loc.host;
	new_uri += loc.pathname + "?ws";
	sock = new WebSocket(new_uri);
	sock.binaryType = "arraybuffer";

	sock.onmessage = function (ev) {
		sock_connected = true;
		console.log(ev);
		var buffer = new Uint8Array(ev.data);
		if(buffer[0] == WS_ADMIN_GET_STATS_RESPONSE) {
			process_ws_admin_get_stats_response(buffer);
		} else if(buffer[0] == WS_ADMIN_PONG) {
			process_pong(buffer);
			console.log("pong received");
		} else if(buffer[0] == WS_ADMIN_GET_MOST_RECENT_RESPONSE) {
			process_get_most_recent_requests(buffer);
		} else {
			console.log("WARNING: Unknown command: " + buffer[0]);
		}
	}

	sock.addEventListener('close', function (event) {
		console.log('disconnected');
		sock_connected = false;
	});

	return sock;
}

function load_requests() {
	let sock = init_listener();
	load_recent_update(sock);

	sock.addEventListener('open', function (event) {
		console.log('connected');
		const buffer = new ArrayBuffer(9);
		const view = new Uint8Array(buffer);
		view[0] = WS_ADMIN_GET_MOST_RECENT_REQUESTS;
		for(var i=1; i<9; i++) {
			view[i] = 0;
		}
		sock.send(buffer);
	});
}

function load_stats() {
	let sock = init_listener();
	ping(sock);

	sock.addEventListener('open', function (event) {
		console.log('connected');
		const buffer = new ArrayBuffer(17);
		const view = new Uint8Array(buffer);
		view[0] = WS_ADMIN_GET_STATS_RESPONSE;
		for(var i=1; i<16; i++) {
			view[i] = 0;
		}
		view[16] = 29;
		sock.send(buffer);
	});

	window.onscroll = function() {
	        if (window.innerHeight + window.pageYOffset >= document.body.offsetHeight &&
			        window.innerHeight + window.pageYOffset > last_scroll) {
			                var link = document.getElementById('load_more');
			                var last = link.last;

			                const buffer = new ArrayBuffer(17);
			                const view = new Uint8Array(buffer);
			                for(var i=0; i<16; i++) {
						                        view[i] = 0;
						                }
			                view[0] = 2;
			                u64_tobin(last, view, 1);
			                view[16] = 30;
			                sock.send(buffer);
			        }
	        last_scroll = window.innerHeight + window.pageYOffset;
}
}
