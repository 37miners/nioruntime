const WS_ADMIN_GET_STATS_RESPONSE                = 0;
const WS_ADMIN_PING                              = 1;
const WS_ADMIN_PONG                              = 1;
const WS_ADMIN_GET_STATS_AFTER_TIMESTAMP_REQUEST = 2;
const WS_ADMIN_GET_MOST_RECENT_REQUESTS          = 3;
const WS_ADMIN_GET_MOST_RECENT_RESPONSE          = 3;
const WS_ADMIN_REQUEST_CHART_REQUEST             = 4;
const WS_ADMIN_REQUEST_CHART_RESPONSE            = 4;
const WS_ADMIN_CREATE_RULE                       = 9;
const WS_ADMIN_CREATE_RULE_RESPONSE              = 9;
const WS_ADMIN_GET_RULES                         = 10;
const WS_ADMIN_GET_RULES_RESPONSE                = 10;
const WS_ADMIN_SET_ACTIVE_RULES                  = 12;
const WS_ADMIN_SET_ACTIVE_RULES_RESPONSE         = 12;
const WS_ADMIN_DELETE_RULE                       = 13;
const WS_ADMIN_DELETE_RULE_RESPONSE              = 13;

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

var rules = [];
var rule_labels = [];
var rule_type = 0;
var lastDragEvent = new Object();
var viewRule;
var globalSortable;
var chart;
var last_scroll = 0;
var mr_micros = 0;
var mr_timestamp = 0;
var first_entry = 0;
var color_alternate = 0;
var sock_connected = true;
var sock;
var pause = false;
var rule_ids = {};
var active_by_id = {};

function show_spinner() {
	$("#spinner_only").modal({backdrop: 'static', keyboard: false});
}

function hide_spinner () {
	$('#spinner_only').modal('hide');
}

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
		var memory_bytes = to_u64(buffer, offset); offset += 8;

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
		var memory_bytes = to_u64(buffer, offset); offset += 8;

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

function format_date(date) {
	var hours = date.getHours();
	var minutes = date.getMinutes();
	var seconds = date.getSeconds();
	var am_pm = 'AM';

	if(seconds < 10) {
		seconds = '0' + seconds;
	}
	if(minutes < 10) {
		minutes = '0' + minutes;
	}

	if(hours == 12) {
		am_pm = 'PM';
	} else if(hours > 12) {
		hours -= 12;
		am_pm = 'PM';
	}

	return hours + ':' + minutes + ':' + seconds + ' ' + am_pm;
}

function process_request_chart_response(buffer) {
        var server_time = to_u64(buffer, 1);
	update_timestamps(server_time);
	var count = to_u64(buffer, 9);
	var offset = 17;

	var server_time = to_u64(buffer, 1);
	var data = [];
	var labels = [];
	var latencies = [];
	var connects_arr = [];
	var memory_bytes_arr = [];
	for (var i=0; i<count; i++) {
		var requests = Number(to_u64(buffer, offset)); offset += 8;
		var latency = Number(to_u64(buffer, offset)); offset += 8;
		var connects = Number(to_u64(buffer, offset)); offset += 8;
		var timestamp = Number(to_u64(buffer, offset)); offset += 8;
		var prev_timestamp = Number(to_u64(buffer, offset)); offset += 8;
		var memory_bytes = Number(to_u64(buffer, offset)); offset += 8;

		var avg_latency = latency / requests;
		var duration = timestamp - prev_timestamp;
		var requests = requests / (duration / 1000);
		var connects = connects / (duration / 1000);
		var memory_bytes = memory_bytes / (1024 * 1024);
		data.push(requests);
		var date = new Date(timestamp);
		labels.push(format_date(date));
		latencies.push(avg_latency);
		connects_arr.push(connects);
		memory_bytes_arr.push(memory_bytes);
	}

	data.reverse();
	labels.reverse();
	latencies.reverse();
	connects_arr.reverse();
	memory_bytes_arr.reverse();

	const requests_data = {
		labels: labels,
		datasets: [{
			label: 'Requests per Second',
			backgroundColor: 'rgb(74, 20, 140)',
			borderColor: 'rgb(74, 20, 140)',
			data,
			}]
		};

	const requests_config = {
		type: 'line',
		data: requests_data,
		options: {}
	};

	const requests_chart = new Chart(
		document.getElementById('requestschart'),
		requests_config
	);

        const memory_data = {
		labels: labels,
		datasets: [{
			label: 'Memory Usage in MB',
			backgroundColor: 'rgb(74, 20, 140)',
			borderColor: 'rgb(74, 20, 140)',
			data: memory_bytes_arr,
		}]
	};

	const memory_config = {
		type: 'line',
		data: memory_data,
		options: {}
	};

	const memory_chart = new Chart(
		document.getElementById('memorychart'),
		memory_config
	);

        const latency_data = {
		labels: labels,
		datasets: [{
			label: 'Average Latency per request in \u03BCs',
			backgroundColor: 'rgb(255, 99, 132)',
			borderColor: 'rgb(255, 99, 132)',
			data: latencies,
		}]
	};

	const latency_config = {
		type: 'line',
		data: latency_data,
		options: {}
	};

	const latency_chart = new Chart(
		document.getElementById('latencychart'),
		latency_config,
	);

	const connections_data = {
		labels: labels,
		datasets: [{ 
			label: 'Connections per second',
			backgroundColor: 'rgb(255, 99, 132)',
			borderColor: 'rgb(255, 99, 132)',
			data: connects_arr,
		}]
	};

	const connections_config = {
		type: 'line',
		data: connections_data,
		options: {}
	};


	const connections_chart = new Chart(
		document.getElementById('connectionschart'),
		connections_config
	);

	document.getElementById('loading').style.display = 'none';
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
		} else if(buffer[0] == WS_ADMIN_REQUEST_CHART_RESPONSE) {
			process_request_chart_response(buffer);
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
	var sock = init_listener();
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
	var sock = init_listener();
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

function load_charts_niohttpd() {
        var sock = init_listener();

	sock.addEventListener('open', function (event) {
		console.log('connected');
		const buffer = new ArrayBuffer(1);
		const view = new Uint8Array(buffer);
		view[0] = WS_ADMIN_REQUEST_CHART_REQUEST;
		sock.send(buffer);
	});

}

function set_active_ids(ids) {
	active_by_id = {};
	for (var i=0; i<ids.length; i++) {
		active_by_id[ids[i]] = true;
	}

	var loc = window.location, new_uri;
		if (loc.protocol === "https:") {
			new_uri = "wss:";
		} else {
			new_uri = "ws:";
	}

        new_uri += "//" + loc.host;
        new_uri += loc.pathname + "?ws";
        var sock = new WebSocket(new_uri);
        sock.binaryType = "arraybuffer";

        sock.onmessage = function (ev) {
                sock_connected = true; 
                console.log(ev); 
                var buffer = new Uint8Array(ev.data);
                if(buffer[0] == WS_ADMIN_SET_ACTIVE_RULES_RESPONSE) {
			console.log("set active successful");
			sock.close();
		} else {
			console.log("Unknown command: " + buffer[0] + " full=" + buffer);
		}
	}

        sock.addEventListener('open', function(event) {
		var count = ids.length;
                const buffer = new ArrayBuffer((8*count) + 9);
                const view = new Uint8Array(buffer);
                view[0] = WS_ADMIN_SET_ACTIVE_RULES;
                view[1] = 0;
                view[2] = 0;
		view[3] = 0;
		view[4] = 0;
		view[5] = 0;
		view[6] = 0;
		view[7] = 0;
		view[8] = count;

		for(var i=0; i<count; i++) {
			u64_tobin(new BigInteger(String(ids[i]), 10), view, 9 + (i*8));
		}

                sock.send(buffer);
        });

	sock.addEventListener('close', function (event) {
		console.log('disconnected');
		sock_connected = false;
	});
}

function get_all_rules() {
	var loc = window.location, new_uri;
	if (loc.protocol === "https:") {
		new_uri = "wss:";
	} else {
		new_uri = "ws:";
	}
	new_uri += "//" + loc.host;
	new_uri += loc.pathname + "?ws";
	var sock = new WebSocket(new_uri);
	sock.binaryType = "arraybuffer";

        sock.onmessage = function (ev) {
		console.log(ev);
		var buffer = new Uint8Array(ev.data);
		if(buffer[0] == WS_ADMIN_GET_RULES_RESPONSE) {
			console.log("get rules response");
			var count = to_u64(buffer, 9);
			console.log("got " + count + " rules.");
			var offset = 17;
			for(var i=0; i<count; i++) {
				// this is a functional rule with an 8 byte id in front
				var functional_id = to_u64(buffer, offset);
				offset += 8;
				var rule = new Rule();
				console.log("offset="+offset);
				offset = rule.deserialize(buffer, offset);
				var is_active;
				if(buffer[offset] == 0) {
					is_active = false;
				} else {
					is_active = true;
				}
				offset += 1; // functional rule is_active flag
				// label
				var label_len = to_u64(buffer, offset);
				offset += 8;
				var label = new ArrayBuffer(label_len);
				var label = new Uint8Array(label);
				for(var j=0; j<label_len; j++) {
					label[j] = buffer[offset];
					offset += 1;
				}
				var label = new TextDecoder().decode(label);
				if(is_active) {
					active_by_id[functional_id] = true;
				}
				rule_ids[label] = functional_id;
				console.log("rule["+i+"] label=" + label + ",id=" + functional_id + ",rule="+rule + ",is_active="+is_active);
				create_dom(label, rule, is_active);
			}
			sock.close();
		} else {
			console.log("Unknown command: " + buffer[0] + " full=" + buffer);
		}
	}

	sock.addEventListener('open', function(event) {
		const buffer = new ArrayBuffer(1);
		const view = new Uint8Array(buffer);
		view[0] = WS_ADMIN_GET_RULES;
		sock.send(buffer);
	});

	sock.addEventListener('close', function (event) {
		console.log('disconnected');
	});
}

function set_active(active_rules) {
	var ids = [];
	for(var i=0; i<active_rules.length; i++) {
		var rule = active_rules[i];
		var child = rule.childNodes[0];
		var label = String(child.childNodes[0].innerHTML);

		console.log('child['+i+']='+label);
		ids.push(rule_ids[label]);
	}
	console.log('set active = ' + active_rules);
	console.log('ids='+ ids);
	set_active_ids(ids);
}

function delete_rule(label) {
	var id = rule_ids[label];
	console.log("active_by_id=" + active_by_id[id] + ",id=" + id);
	if(active_by_id[id] == true) {
		document.getElementById('modal_error_text').innerHTML =
			'You cannot delete active rules. Make this rule inactive first.';
		$("#error_modal").modal();
		return false;
	}
	delete_rule_dom(label);
	var loc = window.location, new_uri;
	if (loc.protocol === "https:") {
		 new_uri = "wss:";
	} else {
		new_uri = "ws:";
	}

	new_uri += "//" + loc.host;
	new_uri += loc.pathname + "?ws";
	var sock = new WebSocket(new_uri);
	sock.binaryType = "arraybuffer";

        sock.onmessage = function (ev) {
		console.log(ev);
		var buffer = new Uint8Array(ev.data);
		if(buffer[0] == WS_ADMIN_DELETE_RULE_RESPONSE) {
			console.log("rule deleted");
			sock.close();
		} else {
			console.log("Unknown command: " + buffer[0] + " full=" + buffer);
		}
	}

        sock.addEventListener('open', function(event) {
		const buffer = new ArrayBuffer(9);
		const view = new Uint8Array(buffer);
		view[0] = WS_ADMIN_DELETE_RULE;
		u64_tobin(new BigInteger(String(id), 10), view, 1);
		console.log("sending buffer = " + view);
		sock.send(buffer);
	});

	sock.addEventListener('close', function (event) {
		console.log('disconnected');
	});

	return true;
}

function create_rule(label_in, rule) {
	var loc = window.location, new_uri;
	if (loc.protocol === "https:") {
		new_uri = "wss:";
	} else {
		new_uri = "ws:";
	}

        new_uri += "//" + loc.host;
        new_uri += loc.pathname + "?ws";
	var sock = new WebSocket(new_uri);
        sock.binaryType = "arraybuffer";
	show_spinner();

	sock.onerror = function (ev) {
		console.log("Error connecting socket - create_rule");
		document.getElementById('modal_error_text').innerHTML =
			'Failure to connect to nioruntime server';
		$("#error_modal").modal();
		hide_spinner();
	}

        sock.onmessage = function (ev) {
                console.log(ev);
                var buffer = new Uint8Array(ev.data);
		hide_spinner();
		if(buffer[0] == WS_ADMIN_CREATE_RULE_RESPONSE) {
			var id = to_u64(buffer, 1);
			console.log("rule created. Id = " + id);
			create_dom(label_in, rule, false);
			rule_ids[label_in] = id;
			sock.close();
		} else {
			console.log("Unknown command: " + buffer[0] + " full=" + buffer);
			document.getElementById('modal_error_text').innerHTML =
				'Unexpected response from nioruntime server. See logs for details.';
			$("#error_modal").modal();
		}
	}

	sock.addEventListener('open', function(event) {
		let label = new TextEncoder().encode(label_in);
		console.log('label='+label);
		var rule_ser = rule.serialize();
		const buffer = new ArrayBuffer(rule_ser.length + label.length + 9);
		const view = new Uint8Array(buffer);
		view[0] = WS_ADMIN_CREATE_RULE;
		for(var i=0; i<rule_ser.length; i++) {
			view[i+1] = rule_ser[i];
		}
		u64_tobin(new BigInteger(String(label.length), 10), view, rule_ser.length + 1);
		var offset = rule_ser.length + 9;
		console.log('label.length=' + label.length);
		for(var i=0; i<label.length; i++) {
			view[i + offset] = label[i];
		}

		console.log("sending buffer = " + view);

		sock.send(buffer);
	});

	sock.addEventListener('close', function (event) {
		console.log('disconnected');
	});
}

function delete_rule_dom(label) {
	console.log('delete rule = ' + label);
	delete globalRules[label];
	delete rule_ids[label];
	var ulitem = document.getElementById('ulitem-' + label);
	ulitem.parentNode.removeChild(ulitem);
}

function set_view_rule(label) {
	var rule = globalRules[label];
	document.getElementById('rule_view_text_area').value = rule.toString();
	document.getElementById('modal-title').innerHTML =
		'Rule Info - ' + label + ' (' + rule_ids[label] + ')';
	viewRule = label;
	var labels = ["Jan", "Feb", "Mar", "Apr", "May"];
	var data = [1,2,3,4,5];
	const chart_data = {
		labels: labels,
		datasets: [{
		label: 'Matches for Pattern \'' + label + '\'',
		backgroundColor: 'rgb(74, 20, 140)',
		borderColor: 'rgb(74, 20, 140)',
		data,
		}]
	};

	const config = {
		type: 'line',
		data: chart_data,
		options: {}
	};

	if (typeof chart === 'undefined') {
		console.log('new chart');
	} else {
		console.log('destroy');
		chart.destroy();
	}

	chart = new Chart(
		document.getElementById('chartdiv'),
		config
	);
}

function create_expr(label, rules, delete_subs) {
	if(label.length == 0) {
		var error_text = document.getElementById("rule_input_error_text");
		error_text.style.display = 'block';
		error_text.innerHTML = 'label must be at least 1 char length';
	} else if(!validateCode(label)) {
		var error_text = document.getElementById("rule_input_error_text");
		error_text.style.display = 'block';
		error_text.innerHTML = 'label must be alpha numeric';
	} else if(typeof(globalRules[label]) != "undefined") {
                var error_text = document.getElementById("rule_input_error_text");
		error_text.style.display = 'block';
		error_text.innerHTML = 'This label already exists';
	} else {
		console.log('create_expr with rules = ' + rules + ',rules.length=' + rules.length + ',cur='+ typeof(globalRules[label]));
		var rule = new Rule(rule_type, rules);
		create_rule(label, rule);
		if(delete_subs == 'true') {
			console.log('delete subs yes');
			for(var i=0; i<rule_labels.length; i++) {
				delete_rule(rule_labels[i]);
			}
		}
		$('#create_rule').modal('hide');
	}
}

function validateCode(code) {
	for (var i = 0; i < code.length; i++) {
		var char1 = code.charAt(i);
		var cc = char1.charCodeAt(0);
		if ((cc > 47 && cc < 58) || (cc > 64 && cc < 91) || (cc > 96 && cc < 123)) {
		} else {
			return false;
		}
	}
	return true;
}

function create_new(label, regex) {
	if(regex.length == 0) {
		var error_text = document.getElementById("pattern_input_error_text");
		error_text.style.display = 'block';
		error_text.innerHTML = 'pattern must be at least 1 char length';
	} else if(regex.startsWith("^") && regex.length == 1) {
		var error_text = document.getElementById("pattern_input_error_text");
		error_text.style.display = 'block';
		error_text.innerHTML = "pattern cannot start with '^' and be length of 1.";
	} else if(label.length == 0) {
		var error_text = document.getElementById("pattern_input_error_text");
		error_text.style.display = 'block';
		error_text.innerHTML = 'label must be at least 1 char length';
	} else if(validateCode(label) == false) {
		console.log('not valid');
		var error_text = document.getElementById("pattern_input_error_text");
		error_text.style.display = 'block';
		error_text.innerHTML = 'label must be alpha numeric';
	} else if(typeof(globalRules[label]) != "undefined") {
		var error_text = document.getElementById("pattern_input_error_text");
		error_text.style.display = 'block';
		error_text.innerHTML = 'This label already exists';
	} else {
		var success = true;
		for(var i=0; i<regex.length; i++) {
			var ch = regex.charAt(i);
			if(ch == '\\' && i == regex.length - 1) {
				var error_text = document.getElementById("pattern_input_error_text");
				error_text.style.display = 'block';
				error_text.innerHTML = 'illegal escape char at the end of the pattern';
				success = false;
			} else if(ch == '\\' && regex.charAt(i+1) != '\\' && regex.charAt(i+1) != '.') {
				var error_text = document.getElementById("pattern_input_error_text");
				error_text.style.display = 'block';
				error_text.innerHTML = "illegal escape char found. '" + '\\' +
				regex.charAt(i+1) + "' is not allowed";
				success = false;
			}
			if(ch == '\\') {
				i++;
			}
		}
		if(success) {
			var rule = new Rule(RULE_TYPE_PATTERN, regex, true);
			create_rule(label, rule);
			//create_dom(label, rule, false);
			$('#pattern_input_modal').modal('hide');
		}
	}
}

function create_dom(label, rule, is_active) {
	console.log('rule='+rule);
	var ul  = document.createElement('li');
	ul.title = label;
	ul.id = 'ulitem-' + label;
	ul.className = "StackedListItem StackedListItem--isDraggable StackedListItem--item1";
	ul.tabindex = 1;
	var div = document.createElement('div');
	div.className = "StackedListContent";

	// create hidden spans with the label and timestamp of last click
	var hidden_label_span = document.createElement('span');
	hidden_label_span.style.display = 'none';
	hidden_label_span.innerHTML = label;
	globalRules[label] = rule;
	lastDragEvent[label] = new Date().getTime();
	div.appendChild(hidden_label_span);
	var h4 = document.createElement('h4');
	h4.className = "Heading Heading--size4 text-no-select";

	var label_truncated = label;
	if(label.length > 9) {
		label_truncated = label.substring(0, 9);
		label_truncated += "..";
	}
	h4.appendChild(document.createTextNode(label_truncated));
	div.appendChild(h4);
	var drag_handle_div = document.createElement('div');
	drag_handle_div.className = 'DragHandle';
	div.appendChild(drag_handle_div);
	var halftone = document.createElement('div');
	halftone.className = "Pattern Pattern--typeHalftone";
	div.appendChild(halftone);
	var placed = document.createElement('div');
	placed.className = "Pattern Pattern--typePlaced";
	div.appendChild(placed);
	ul.appendChild(div);
	var ulh;
	if(is_active) {
		ulh = document.getElementById('ulactive');
	} else {
		ulh = document.getElementById('ulinactive');
	}
	ulh.appendChild(ul);
}

	function clear_modals() {
		var error_text = document.getElementById("pattern_input_error_text");
		error_text.style.display = 'none';
		var error_text = document.getElementById("rule_input_error_text");
		error_text.style.display = 'none';
		document.forms['pattern_input']['label'].value = '';
		document.forms['pattern_input']['regex'].value = '';
		document.getElementById('help_info').style.display='none';
		document.forms['confirm_rule']['label'].value = '';
	}

	function do_modal() {
		clear_modals();
		$("#pattern_input_modal").modal();
	}

	function do_and_rule() {
		var uland = document.getElementById('uland');
		var children = uland.childNodes;
		rules = [];
		rule_labels = [];
		for(var i=0; i<children.length; i++) {
			var child = children[i].childNodes[0];
			var label = String(child.childNodes[0].innerHTML);
			rule_labels.push(label);
			console.log('pushing label='+label);
			var rule = globalRules[label];
			rules.push(rule);
		}

		if(rules.length < 2) {
			document.getElementById('modal_error_text').innerHTML = 'At least 2 rules required for and';
			$("#error_modal").modal();
		} else {
			rule_type = RULE_TYPE_AND;
			document.forms['confirm_rule']['label'].value = '';
			document.getElementById('help_info_rule').style.display='none';
			console.log('creating new rule with rules = ' + rules + ',rules.length='+rules.length);
			var rule = new Rule(rule_type, rules);
			console.log('complete rule='+rule);
			document.getElementById('rule_text_area').value = rule.toString();
			clear_modals();
			$("#create_rule").modal();
		}
	}

	function do_or_rule() {
		var ulor = document.getElementById('ulor');
		var children = ulor.childNodes;
		rules = [];
		rule_labels = [];
		for(var i=0; i<children.length; i++) {
			var child = children[i].childNodes[0];
			var label = String(child.childNodes[0].innerHTML);
			rule_labels.push(label);
			console.log('pushing label='+label);
			var rule = globalRules[label];
			rules.push(rule);
		}

		if(rules.length < 2) {
			document.getElementById('modal_error_text').innerHTML = 'At least 2 rules required for or';
			$("#error_modal").modal();
		} else {
			rule_type = RULE_TYPE_OR;
			document.forms['confirm_rule']['label'].value = '';
			document.getElementById('help_info_rule').style.display='none';
			var rule = new Rule(rule_type, rules);
			console.log('rule='+rule);
			document.getElementById('rule_text_area').value = rule.toString();
			clear_modals();
			$("#create_rule").modal();
		}
	}

	function do_not_rule() {
		var ulnot = document.getElementById('ulnot');
		var children = ulnot.childNodes;
		rules = [];
		rule_labels = [];
		for(var i=0; i<children.length; i++) {
			var child = children[i].childNodes[0];
			var label = child.childNodes[0].innerHTML;
			rule_labels.push(label);
			var rule = globalRules[label];
			rules.push(rule);
			console.log('child[' + i + ']= ' + label + ',rule=' + globalRules[label]);
		}

		if(rules.length < 1) {
			document.getElementById('modal_error_text').innerHTML = 'Not requires 1 rule';
			$("#error_modal").modal();
		} else {
			rule_type = RULE_TYPE_NOT;
			document.forms['confirm_rule']['label'].value = '';
			document.getElementById('help_info_rule').style.display='none';
			var rule = new Rule(rule_type, rules);
			console.log('rule='+rule);
			document.getElementById('rule_text_area').value = rule.toString();
			clear_modals();
			$("#create_rule").modal();
		}
	}

	function openMulti() {
		if (document.querySelector(".selectWrapper").style.pointerEvents == "all") {
			document.querySelector(".selectWrapper").style.opacity = 0;
			document.querySelector(".selectWrapper").style.pointerEvents = "none";
			resetAllMenus();
		} else {
			document.querySelector(".selectWrapper").style.opacity = 1;
			document.querySelector(".selectWrapper").style.pointerEvents = "all";
		}
	}

function nextMenu(e) {
	menuIndex = eval(event.target.parentNode.id.slice(-1));
	document.querySelectorAll(".multiSelect")[menuIndex].style.transform =
		"translateX(-100%)";
	document.querySelectorAll(".multiSelect")[menuIndex].style.clipPath =
		"polygon(100% 0, 100% 0, 100% 100%, 100% 100%)";
	document.querySelectorAll(".multiSelect")[menuIndex + 1].style.transform =
		"translateX(0)";
	document.querySelectorAll(".multiSelect")[menuIndex + 1].style.clipPath =
		"polygon(0 0, 100% 0, 100% 100%, 0% 100%)";
}

function prevMenu(e) {
	menuIndex = eval(event.target.parentNode.id.slice(-1));
	document.querySelectorAll(".multiSelect")[menuIndex].style.transform =
		"translateX(100%)";
	document.querySelectorAll(".multiSelect")[menuIndex].style.clipPath =
		"polygon(0 0, 0 0, 0 100%, 0% 100%)";
	document.querySelectorAll(".multiSelect")[menuIndex - 1].style.transform =
		"translateX(0)";
	document.querySelectorAll(".multiSelect")[menuIndex - 1].style.clipPath =
		"polygon(0 0, 100% 0, 100% 100%, 0% 100%)";
}

function resetAllMenus() {
	setTimeout(function () {
	var x = document.getElementsByClassName("multiSelect");
	var i;
	for (i = 1; i < x.length; i++) {
		x[i].style.transform = "translateX(100%)";
		x[i].style.clipPath = "polygon(0 0, 0 0, 0 100%, 0% 100%)";
	}
	document.querySelectorAll(".multiSelect")[0].style.transform =
		"translateX(0)";
	document.querySelectorAll(".multiSelect")[0].style.clipPath =
		"polygon(0 0, 100% 0, 100% 100%, 0% 100%)";
	}, 300);
}
