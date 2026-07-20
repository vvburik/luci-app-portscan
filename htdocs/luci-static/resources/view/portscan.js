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
			exec('/usr/sbin/nft', ['list', 'set', 'inet', 'fw4', 'portscan_blacklist']).catch(function(e) { return { code: 1, stderr: e.message }; }),
			exec('/usr/sbin/nft', ['list', 'set', 'inet', 'fw4', 'portscan_permanent']).catch(function(e) { return { code: 1, stderr: e.message }; })
		]);
	},

	render: function(data) {
		var nft_data_blacklist = data[0];
		var nft_data_permanent = data[1];
		var m, s, o;

		function saveCache() {
			return exec('/etc/init.d/portscan', ['save_cache']);
		}

		m = new form.Map('portscan', 'Port Scan Protection',
			'Here you can configure port scan protection rules and view actively blocked IPs. <br/><em>Note: Manual blocks are saved immediately. Automatic blocks are kept in memory and saved to disk only during a graceful reboot to prevent flash wear.</em>');

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

			// Manual Block UI
			var manualBlockDiv = E('div', { 'class': 'cbi-value', 'style': 'margin-bottom: 20px;' }, [
				E('label', { 'class': 'cbi-value-title' }, 'Manual Block'),
				E('div', { 'class': 'cbi-value-field' }, [
					E('div', { 'style': 'display: flex; flex-wrap: wrap; gap: 10px; align-items: center;' }, [
						E('input', { 'type': 'text', 'id': 'manual_ip', 'placeholder': '1.2.3.4' }),
						E('input', { 'type': 'text', 'id': 'manual_time', 'placeholder': 'Permanent' }),
						E('button', {
							'class': 'btn cbi-button cbi-button-apply',
							'click': function() {
								var ip = document.getElementById('manual_ip').value.trim();
								var time = document.getElementById('manual_time').value.trim();
								if (!ip) {
									ui.addNotification(null, E('p', 'Please enter an IP address.'));
									return;
								}
								var args = ['add', 'element', 'inet', 'fw4'];
								if (time) {
									args = args.concat(['portscan_blacklist', '{', ip, 'timeout', time, '}']);
								} else {
									args = args.concat(['portscan_permanent', '{', ip, '}']);
								}
								exec('/usr/sbin/nft', args).then(function(res) {
									if (res && res.code !== 0) {
										ui.addNotification(null, E('p', 'Error: ' + res.stderr));
									} else {
										document.getElementById('manual_ip').value = '';
										document.getElementById('manual_time').value = '';
										saveCache().then(function() { refreshTable(); });
									}
								}).catch(function(e) {
									ui.addNotification(null, E('p', 'RPC Error: ' + e.message));
								});
							}
						}, 'Block IP')
					]),
					E('div', { 'class': 'cbi-value-description' }, 'Enter an IP address to block. Specify a time (e.g., 30d, 12h) or leave the time field empty for a permanent block.')
				])
			]);

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
					if (confirm('Are you sure you want to clear all blocked IPs (dynamic and permanent)?')) {
						exec('/usr/sbin/nft', ['flush', 'set', 'inet', 'fw4', 'portscan_blacklist']).then(function(){
							exec('/usr/sbin/nft', ['flush', 'set', 'inet', 'fw4', 'portscan_permanent']).then(function(){
								saveCache().then(function() { refreshTable(); });
							});
						});
					}
				}
			}, 'Clear all entries');

			function formatExpires(str) {
				return str.replace(/[0-9]+ms/g, '')
				          .replace(/([dhms])/g, '$1 ')
				          .trim();
			}

			function updateTableDOM(out1, err1, code1, out2, err2, code2) {
				// Remove all rows except the header
				while (table.childNodes.length > 1) {
					table.removeChild(table.lastChild);
				}

				var entries = [];
				var combinedStderr = '';

				if (code1 !== 0 && err1) combinedStderr += err1 + ' ';
				if (code2 !== 0 && err2) combinedStderr += err2 + ' ';

				// Parse dynamic blocks
				if (out1) {
					var regex = /([a-fA-F0-9\.\:]+)\s+(?:timeout\s+[0-9a-z]+\s+)?expires\s+([0-9a-z]+)/g;
					var match;
					while ((match = regex.exec(out1)) !== null) {
						entries.push({ ip: match[1], expires: formatExpires(match[2]), set: 'portscan_blacklist' });
					}
				}

				// Parse permanent blocks
				if (out2) {
					var matchPerm = out2.match(/elements\s*=\s*\{\s*([^}]+)\s*\}/);
					if (matchPerm && matchPerm[1]) {
						var parts = matchPerm[1].split(/[\s,]+/);
						parts.forEach(function(p) {
							if (p.match(/^[0-9a-fA-F\.\:]+$/)) {
								entries.push({ ip: p, expires: 'Permanent', set: 'portscan_permanent' });
							}
						});
					}
				}

				if (combinedStderr) {
					table.appendChild(E('tr', { 'class': 'tr placeholder' }, [
						E('td', { 'class': 'td', 'colspan': '3' }, 'Error: ' + combinedStderr)
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
						var actionsDiv = E('div', { 'style': 'display: flex; flex-wrap: wrap; gap: 5px; justify-content: center;' });

						// Remove Button
						var btnDelete = E('button', {
							'class': 'btn cbi-button cbi-button-remove',
							'click': function() {
								exec('/usr/sbin/nft', ['delete', 'element', 'inet', 'fw4', entry.set, '{', entry.ip, '}']).then(function(res) {
									if (res && res.code !== 0) ui.addNotification(null, E('p', 'Error: ' + res.stderr));
									else saveCache().then(function() { refreshTable(); });
								});
							}
						}, 'Remove');
						actionsDiv.appendChild(btnDelete);

						// Make Permanent Button
						if (entry.set === 'portscan_blacklist') {
							var btnPerm = E('button', {
								'class': 'btn cbi-button cbi-button-neutral',
								'click': function() {
									exec('/usr/sbin/nft', ['delete', 'element', 'inet', 'fw4', 'portscan_blacklist', '{', entry.ip, '}']).then(function() {
										exec('/usr/sbin/nft', ['add', 'element', 'inet', 'fw4', 'portscan_permanent', '{', entry.ip, '}']).then(function() {
											saveCache().then(function() { refreshTable(); });
										});
									});
								}
							}, 'Make Permanent');
							actionsDiv.appendChild(btnPerm);
						}

						// Change Time Button
						var btnTime = E('button', {
							'class': 'btn cbi-button cbi-button-action',
							'click': function() {
								var newTime = prompt('Enter new block time for ' + entry.ip + ' (e.g. 30d, 12h, 5m):', '30d');
								if (!newTime) return;
								exec('/usr/sbin/nft', ['delete', 'element', 'inet', 'fw4', entry.set, '{', entry.ip, '}']).then(function() {
									exec('/usr/sbin/nft', ['add', 'element', 'inet', 'fw4', 'portscan_blacklist', '{', entry.ip, 'timeout', newTime, '}']).then(function(res) {
										if (res && res.code !== 0) ui.addNotification(null, E('p', 'Error: ' + res.stderr));
										else saveCache().then(function() { refreshTable(); });
									});
								});
							}
						}, 'Change Time');
						actionsDiv.appendChild(btnTime);

						table.appendChild(E('tr', { 'class': 'tr cbi-rowstyle-' + ((index % 2 === 0) ? '1' : '2') }, [
							E('td', { 'class': 'td left', 'data-title': 'IP Address' }, entry.ip),
							E('td', { 'class': 'td left', 'data-title': 'Expires In' }, entry.expires),
							E('td', { 'class': 'td center cbi-section-actions', 'data-title': 'Actions' }, actionsDiv)
						]));
					});
				}
			}

			function refreshTable(btnRef) {
				if (btnRef) btnRef.disabled = true;
				Promise.all([
					exec('/usr/sbin/nft', ['list', 'set', 'inet', 'fw4', 'portscan_blacklist']).catch(function(e){ return { code: 1, stderr: e.message }; }),
					exec('/usr/sbin/nft', ['list', 'set', 'inet', 'fw4', 'portscan_permanent']).catch(function(e){ return { code: 1, stderr: e.message }; })
				]).then(function(results) {
					updateTableDOM(results[0].stdout, results[0].stderr, results[0].code,
					               results[1].stdout, results[1].stderr, results[1].code);
					if (btnRef) btnRef.disabled = false;
				});
			}

			// Initial render
			updateTableDOM(
				nft_data_blacklist ? nft_data_blacklist.stdout : '', nft_data_blacklist ? nft_data_blacklist.stderr : '', nft_data_blacklist ? nft_data_blacklist.code : 0,
				nft_data_permanent ? nft_data_permanent.stdout : '', nft_data_permanent ? nft_data_permanent.stderr : '', nft_data_permanent ? nft_data_permanent.code : 0
			);

			return E('div', {}, [
				manualBlockDiv,
				table,
				E('div', { 'class': 'right', 'style': 'margin-top: 10px; margin-bottom: 2rem; display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 10px;' }, [
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
