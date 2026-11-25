/**
 * AGuard Safe admin script: confirmation prompts and the "Check now" dialog,
 * which runs the site check step by step over admin-ajax and shows the result of each step.
 * This file is the source: it is not minified and no build tools are used.
 */
(function () {
	'use strict';

	// Ask before a destructive action: forms and buttons marked with data-ag-confirm.
	document.addEventListener('submit', function (e) {
		var text = e.target.getAttribute && e.target.getAttribute('data-ag-confirm');
		if (text && !window.confirm(text)) {
			e.preventDefault();
		}
	});
	document.addEventListener('click', function (e) {
		var button = e.target.closest ? e.target.closest('button[data-ag-confirm]') : null;
		if (button && !window.confirm(button.getAttribute('data-ag-confirm'))) {
			e.preventDefault();
		}
	});

	var modal = document.getElementById('ag-scan');
	var openButton = document.getElementById('ag-scan-btn');
	if (!modal || !openButton) {
		return;
	}

	var cfg = window.aguardSafe || {};
	var goButton = document.getElementById('ag-scan-go');
	var closeButton = document.getElementById('ag-scan-close');
	var result = document.getElementById('ag-scan-res');
	var rows = [].slice.call(modal.querySelectorAll('li[data-step]'));
	var busy = false;

	function closeModal() {
		if (!busy) {
			modal.hidden = true;
		}
	}

	openButton.onclick = function () {
		modal.hidden = false;
	};
	closeButton.onclick = closeModal;
	modal.addEventListener('click', function (e) {
		if (e.target === modal) {
			closeModal();
		}
	});
	document.addEventListener('keydown', function (e) {
		if (e.key === 'Escape') {
			closeModal();
		}
	});

	function postStep(step) {
		var body = new FormData();
		body.append('action', 'aguard_safe_scan_step');
		body.append('nonce', cfg.scanNonce);
		body.append('step', step);
		return fetch(window.ajaxurl, { method: 'POST', credentials: 'same-origin', body: body }).then(function (r) {
			return r.json();
		});
	}

	function rowFor(step) {
		for (var i = 0; i < rows.length; i++) {
			if (rows[i].getAttribute('data-step') === step) {
				return rows[i];
			}
		}
		return null;
	}

	function setStatus(row, text, spinner) {
		var cell = row.querySelector('.ag-sr');
		cell.textContent = '';
		if (spinner) {
			var spin = document.createElement('span');
			spin.className = 'ag-spin';
			cell.appendChild(spin);
		}
		cell.appendChild(document.createTextNode(text));
	}

	function unlock() {
		goButton.disabled = false;
		closeButton.disabled = false;
		busy = false;
	}

	function start() {
		if (busy) {
			return;
		}
		busy = true;
		goButton.disabled = true;
		closeButton.disabled = true;
		result.textContent = '';
		rows.forEach(function (row) {
			row.className = '';
			setStatus(row, cfg.waiting, false);
		});

		var startedAt = Date.now();
		var queue = ['start'].concat(rows.map(function (row) {
			return row.getAttribute('data-step');
		}), ['finish']);
		var index = 0;

		function next() {
			var step = queue[index++];
			var row = rowFor(step);
			if (row) {
				row.className = 'run';
				setStatus(row, cfg.checking, true);
			}
			postStep(step).then(function (json) {
				if (!json || !json.success) {
					throw new Error((json && json.data && json.data.msg) || cfg.serverError);
				}
				var data = json.data;
				if (row) {
					row.className = 'done ag-' + (data.state || 'info');
					setStatus(row, data.text + (data.ms > 1500 ? ' · ' + Math.round(data.ms / 1000) + ' ' + cfg.seconds : ''), false);
				}
				if (step === 'finish') {
					var took = Math.round((Date.now() - startedAt) / 1000);
					result.className = 'ag-res ag-' + (data.state || 'info');
					result.textContent = String(cfg.finished).replace('%d', took) + ' ' + data.text;
					goButton.textContent = cfg.refresh;
					goButton.onclick = function () {
						window.location.reload();
					};
					unlock();
					return;
				}
				next();
			}).catch(function (e) {
				if (row) {
					row.className = 'done ag-risk';
					setStatus(row, cfg.stepFailed + ' ' + e.message, false);
				}
				result.className = 'ag-res ag-risk';
				result.textContent = cfg.failed;
				unlock();
			});
		}
		next();
	}

	goButton.onclick = start;
})();
