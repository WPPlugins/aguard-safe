/**
 * AGuard Safe admin script: confirmation prompts and the "Check now" dialog,
 * which runs the site check step by step over admin-ajax and shows the result of each step.
 * This file is the source: it is not minified and no build tools are used.
 */
(function () {
	'use strict';

	// 7-day chart: the figures of the day under the pointer (or in keyboard focus) are shown in the card header in place of the legend.
	var chart = document.querySelector('.aguard .ag-chart');
	var readout = chart && chart.querySelector('.ag-readout');
	if (readout) {
		var show = function (e) {
			var day = e.target.closest ? e.target.closest('.ag-day') : null;
			if (!day || !day.getAttribute('data-ag-tip')) { return; }
			readout.textContent = day.getAttribute('data-ag-tip');
			chart.classList.add('ag-on');
		};
		var hide = function () { chart.classList.remove('ag-on'); };
		chart.addEventListener('mouseover', show);
		chart.addEventListener('focusin', show);
		chart.addEventListener('mouseleave', hide);
		chart.addEventListener('focusout', hide);
	}

	// Scan results opened from a note: bring the row it was about into view.
	var target = document.querySelector('.aguard [data-ag-target]');
	if (target) { target.scrollIntoView({ block: 'center' }); }

	// File viewer: go straight to the first line the scan pointed at.
	var hit = document.querySelector('.aguard .ag-ln-hit');
	if (hit && !window.location.hash) {
		hit.scrollIntoView({ block: 'center' });
	}

	// First-run window: focus the main button; Escape means "remind me later".
	var setup = document.getElementById('ag-setup-modal');
	if (setup) {
		var main = setup.querySelector('button[name="aguard_setup_all"]');
		if (main) {
			main.focus();
		}
		document.addEventListener('keydown', function (e) {
			var later = document.getElementById('ag-setup-later');
			if (e.key === 'Escape' && later) {
				later.click();
			}
		});
	}

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

	// A check that runs while the next page loads: say so, otherwise the click looks ignored.
	document.addEventListener('click', function (e) {
		var link = e.target.closest ? e.target.closest('a[data-ag-busy]') : null;
		var root = document.querySelector('.aguard');
		if (!link || !root || e.metaKey || e.ctrlKey || e.shiftKey || e.button) {
			return;
		}
		if (root.classList.contains('ag-working')) {
			e.preventDefault();
			return;
		}
		root.classList.add('ag-working');
		link.classList.add('ag-busy');
		var note = document.createElement('div');
		note.className = 'ag-toast';
		note.setAttribute('role', 'status');
		var spin = document.createElement('span');
		spin.className = 'ag-spin';
		note.appendChild(spin);
		note.appendChild(document.createTextNode((window.aguardSafe && window.aguardSafe.busy) || '…'));
		root.appendChild(note);
	});
	window.addEventListener('pageshow', function (e) {
		var root = document.querySelector('.aguard');
		if (e.persisted && root) {
			root.classList.remove('ag-working');
			[].forEach.call(root.querySelectorAll('.ag-toast'), function (n) { n.parentNode.removeChild(n); });
			[].forEach.call(root.querySelectorAll('.ag-busy'), function (n) { n.classList.remove('ag-busy'); });
		}
	});

	// "Details" on the Overview: go to the list and mark it for a moment, also when the list is already on the screen.
	var todoButton = document.getElementById('ag-todo-btn');
	var todo = document.getElementById('ag-todo');
	function showTodo() {
		var calm = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
		todo.scrollIntoView({ behavior: calm ? 'auto' : 'smooth', block: 'center' });
		todo.classList.remove('ag-flash');
		void todo.offsetWidth;
		todo.classList.add('ag-flash');
	}
	if (todoButton && todo) {
		todoButton.addEventListener('click', function (e) {
			e.preventDefault();
			showTodo();
		});
		if (window.location.hash === '#ag-todo') {
			showTodo();
		}
	}

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
			var old = row.querySelector('.ag-step-open');
			if (old) {
				row.removeChild(old);
			}
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
					if (data.open) {
						var link = document.createElement('a');
						link.className = 'ag-step-open';
						link.href = data.open;
						link.textContent = cfg.open + ' →';
						row.appendChild(link);
					}
				}
				if (step === 'finish') {
					var took = Math.round((Date.now() - startedAt) / 1000);
					result.className = 'ag-res ag-' + (data.state || 'info');
					result.textContent = String(cfg.finished).replace('%d', took) + ' ' + data.text;
					goButton.textContent = data.todo ? cfg.todo : cfg.refresh;
					goButton.onclick = function () {
						if (data.todo) {
							window.location.hash = 'ag-todo';
						}
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
