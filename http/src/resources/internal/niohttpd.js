const WS_ADMIN_GET_STATS_RESPONSE = 0;

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

function process_ws_admin_get_stats_response(buffer) {
	let count = to_u64(buffer, 1);
	console.log('count='+count);
	let offset = 9;

	var table = document.createElement('table');
	var tr = document.createElement('tr');

        var td = document.createElement('td');
	td.className = 'table_heading';
	td.appendChild(document.createTextNode('Requests'));
	tr.appendChild(td);

        var td = document.createElement('td');
	td.className = 'table_heading';
	td.appendChild(document.createTextNode('Log Drops'));
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
	td.appendChild(document.createTextNode('Timestamp'));
	tr.appendChild(td);

        var td = document.createElement('td');
	td.className = 'table_heading';
	td.appendChild(document.createTextNode('Prev Timestamp'));
	tr.appendChild(td);

        var td = document.createElement('td');
	td.className = 'table_heading';
	td.appendChild(document.createTextNode('Startup Time'));
	tr.appendChild(td);

	table.appendChild(tr);

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
		console.log('record { requests: ' + requests + ', timestamp: ' + timestamp);

		var tr = document.createElement('tr');
		
		var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(requests));
		tr.appendChild(td);

                var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(dropped_log));
		tr.appendChild(td);

                var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(conns)); 
		tr.appendChild(td);

		var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(connects));
		tr.appendChild(td);


		var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(disconnects));
		tr.appendChild(td);

		var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(connect_timeouts));
		tr.appendChild(td);

		var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(read_timeouts));
		tr.appendChild(td);

		var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(timestamp));
		tr.appendChild(td);

		var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(prev_timestamp));
		tr.appendChild(td);

		var td = document.createElement('td');
		if (i % 2 == 0) { td.className = 'table_odd'; } else { td.className = 'table_even'; }
		td.appendChild(document.createTextNode(startup_time));
		tr.appendChild(td);

		table.appendChild(tr);
	}

	statsdiv.innerHTML = '';
	statsdiv.appendChild(table);
}

function load_stats() {
	var loc = window.location, new_uri;
	if (loc.protocol === "https:") {
		new_uri = "wss:";
	} else {
		new_uri = "ws:";
	}
	new_uri += "//" + loc.host;
	new_uri += loc.pathname + "?ws";
	console.log('new_uri='+new_uri);
	var sock = new WebSocket(new_uri);
	sock.binaryType = "arraybuffer";
	sock.onclose = function(ev) {
		console.log("websocket closed");
	}
	sock.onmessage = function (ev) {
		console.log(ev);
		var buffer = new Uint8Array(ev.data);
		if(buffer[0] == WS_ADMIN_GET_STATS_RESPONSE) {
			process_ws_admin_get_stats_response(buffer);
		} else {
			console.log("WARNING: Unknown command: " + buffer[0]);
		}
	}

	sock.addEventListener('open', function (event) {
		console.log('connected');
		const buffer = new ArrayBuffer(17);
		const view = new Uint8Array(buffer);
		for(var i=0; i<16; i++) {
			view[i] = 0;
		}
		view[16] = 29;
		sock.send(buffer);
	});
}
