'use strict';

'require view';
'require rpc';
'require ui';
'require form';

var exec = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ]
});

return view.extend({
	load: function() {
		return Promise.all([
			exec('/usr/sbin/nft', ['list', 'set', 'inet', 'fw4', 'portscan_blacklist']).catch(function(e) { return { code: 1, stderr: e.message }; })
		]);
	},

	render: function(data) {
		var nft_data = data[0];
		var m, s, o;

		m = new form.Map('portscan', 'Port Scan Protection',
			'Here you can configure port scan protection rules and view actively blocked IPs.');

		// Settings Section
		s = m.section(form.TypedSection, 'portscan', 'Settings');
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.Flag, 'enable', 'Enable Protection');
		o.rmempty = false;

		o = s.option(form.Value, 'timeout', 'Block Timeout', 'How long an IP stays blocked (e.g., 12h, 30m, 1d)');
		o.default = '12h';
		o.rmempty = false;

		o = s.option(form.Value, 'limit_rate', 'Rate Limit', 'Number of SYN packets allowed per minute');
		o.datatype = 'uinteger';
		o.default = '15';
		o.rmempty = false;

		o = s.option(form.Value, 'limit_burst', 'Burst Limit', 'Maximum allowed burst of SYN packets');
		o.datatype = 'uinteger';
		o.default = '10';
		o.rmempty = false;

		// Active Blocks Section
		s = m.section(form.TypedSection, 'portscan', 'Active Blocks');
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.DummyValue, '_blacklist');
		o.rawhtml = true;
		o.render = function() {
			var table = E('table', { 'class': 'table cbi-section-table', 'id': 'portscan_table' }, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th left' }, 'IP Address'),
					E('th', { 'class': 'th left' }, 'Expires In'),
					E('th', { 'class': 'th center cbi-section-actions' }, 'Actions')
				])
			]);

			var btnClear = E('button', {
				'class': 'btn cbi-button cbi-button-reset',
				'click': function(){
					if (confirm('Are you sure you want to clear the entire blacklist?')) {
						exec('/usr/sbin/nft', ['flush', 'set', 'inet', 'fw4', 'portscan_blacklist']).then(function(res){
							refreshTable();
						});
					}
				}
			}, 'Clear all entries');

			function formatExpires(str) {
				return str.replace(/[0-9]+ms/g, '')
				          .replace(/([dhms])/g, '$1 ')
				          .trim();
			}

			function updateTableDOM(stdout, stderr, code) {
				// Remove all rows except the header
				while (table.childNodes.length > 1) {
					table.removeChild(table.lastChild);
				}

				var entries = [];
				if (stdout) {
					var regex = /([a-fA-F0-9\.\:]+)\s+expires\s+([0-9a-z]+)/g;
					var match;
					while ((match = regex.exec(stdout)) !== null) {
						entries.push({ ip: match[1], expires: formatExpires(match[2]) });
					}
				}

				if (code !== 0 && stderr) {
					table.appendChild(E('tr', { 'class': 'tr placeholder' }, [
						E('td', { 'class': 'td', 'colspan': '3' }, 'Error: ' + stderr)
					]));
					btnClear.disabled = true;
				} else if (entries.length === 0) {
					table.appendChild(E('tr', { 'class': 'tr placeholder' }, [
						E('td', { 'class': 'td', 'colspan': '3' }, E('em', {}, 'No blacklist entries currently.'))
					]));
					btnClear.disabled = true;
				} else {
					btnClear.disabled = false;
					entries.forEach(function(entry, index) {
						var btnDelete = E('button', {
							'class': 'btn cbi-button cbi-button-remove',
							'click': function(ev) {
								var row = ev.target.closest('tr');
								exec('/usr/sbin/nft', ['delete', 'element', 'inet', 'fw4', 'portscan_blacklist', '{', entry.ip, '}']).then(function(res) {
									if (res && res.code !== 0) {
										ui.addNotification(null, E('p', 'Error deleting ' + entry.ip + ': ' + res.stderr));
									} else {
										row.parentNode.removeChild(row);
										if (table.querySelectorAll('tr.cbi-rowstyle-1, tr.cbi-rowstyle-2').length === 0) {
											updateTableDOM('', '', 0); // show empty state
										}
									}
								}).catch(function(e) {
									ui.addNotification(null, E('p', 'RPC Error: ' + e.message));
								});
							}
						}, 'Remove');

						table.appendChild(E('tr', { 'class': 'tr cbi-rowstyle-' + ((index % 2 === 0) ? '1' : '2') }, [
							E('td', { 'class': 'td left', 'data-title': 'IP Address' }, entry.ip),
							E('td', { 'class': 'td left', 'data-title': 'Expires In' }, entry.expires),
							E('td', { 'class': 'td center cbi-section-actions', 'data-title': 'Actions' }, btnDelete)
						]));
					});
				}
			}

			function refreshTable(btnRef) {
				if (btnRef) btnRef.disabled = true;
				exec('/usr/sbin/nft', ['list', 'set', 'inet', 'fw4', 'portscan_blacklist']).then(function(res) {
					updateTableDOM(res.stdout, res.stderr, res.code);
					if (btnRef) btnRef.disabled = false;
				}).catch(function(e) {
					ui.addNotification(null, E('p', 'RPC Error: ' + e.message));
					if (btnRef) btnRef.disabled = false;
				});
			}

			// Initial render
			updateTableDOM(nft_data ? nft_data.stdout : '', nft_data ? nft_data.stderr : '', nft_data ? nft_data.code : 0);

			return E('div', {}, [
				table,
				E('div', { 'class': 'right', 'style': 'margin-top: 10px; display: flex; justify-content: flex-end; gap: 10px;' }, [
					E('button', {
						'class': 'btn cbi-button cbi-button-neutral',
						'click': function(ev) {
							refreshTable(ev.target);
						}
					}, 'Refresh'),
					btnClear
				])
			]);
		};

		return m.render();
	}
});
