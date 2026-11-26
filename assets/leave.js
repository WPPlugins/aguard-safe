/* AGuard Safe: asks why before the plugin is turned off. Skipping sends nothing. */
( function () {
	'use strict';
	var L = window.aguardSafeLeave;
	if ( ! L || ! window.HTMLDialogElement ) {
		return;
	}
	var link = null;
	document.querySelectorAll( 'tr[data-plugin]' ).forEach( function ( tr ) {
		if ( tr.getAttribute( 'data-plugin' ) === L.plugin ) {
			link = tr.querySelector( '.deactivate a' );
		}
	} );
	if ( ! link ) {
		return;
	}

	function el( tag, cls, text ) {
		var n = document.createElement( tag );
		if ( cls ) {
			n.className = cls;
		}
		if ( text ) {
			n.textContent = text;
		}
		return n;
	}

	var dlg = el( 'dialog', 'aguard-leave' ), form = el( 'form' );
	dlg.setAttribute( 'aria-labelledby', 'aguard-leave-title' );
	var h = el( 'h2', '', L.title );
	h.id = 'aguard-leave-title';
	form.appendChild( h );
	form.appendChild( el( 'p', '', L.lead ) );

	var hint = el( 'p', 'aguard-leave__hint', L.mailHint + ' ' );
	var a = el( 'a', '', L.mailLink );
	a.href = L.settings;
	hint.appendChild( a );
	hint.hidden = true;

	Object.keys( L.reasons ).forEach( function ( key ) {
		var label = el( 'label' ), r = el( 'input' );
		r.type = 'radio';
		r.name = 'aguard_leave_reason';
		r.value = key;
		label.appendChild( r );
		label.appendChild( document.createTextNode( L.reasons[ key ] ) );
		form.appendChild( label );
		if ( key === 'mail' ) {
			form.appendChild( hint );
		}
	} );

	var text = el( 'textarea' );
	text.maxLength = 1000;
	text.placeholder = L.placeholder;
	text.setAttribute( 'aria-label', L.placeholder );
	form.appendChild( text );
	form.appendChild( el( 'p', 'aguard-leave__note', L.discloses ) );

	var act = el( 'div', 'aguard-leave__act' );
	var send = el( 'button', 'button button-primary', L.send );
	send.type = 'submit';
	send.disabled = true;
	var skip = el( 'button', 'button', L.skip );
	skip.type = 'button';
	var cancel = el( 'button', 'button-link aguard-leave__cancel', L.cancel );
	cancel.type = 'button';
	act.appendChild( send );
	act.appendChild( skip );
	act.appendChild( cancel );
	form.appendChild( act );
	dlg.appendChild( form );
	document.body.appendChild( dlg );

	function chosen() {
		var r = form.querySelector( 'input[name="aguard_leave_reason"]:checked' );
		return r ? r.value : '';
	}
	function go() {
		window.location.href = link.href;
	}

	form.addEventListener( 'change', function () {
		send.disabled = ! chosen();
		hint.hidden = chosen() !== 'mail';
	} );
	link.addEventListener( 'click', function ( e ) {
		e.preventDefault();
		dlg.showModal();
	} );
	cancel.addEventListener( 'click', function () {
		dlg.close();
	} );
	skip.addEventListener( 'click', go );
	form.addEventListener( 'submit', function ( e ) {
		e.preventDefault();
		send.disabled = true;
		skip.disabled = true;
		var body = new URLSearchParams( { action: 'aguard_safe_leave', nonce: L.nonce, reason: chosen(), text: text.value } );
		var done = false, finish = function () {
			if ( ! done ) {
				done = true;
				go();
			}
		};
		window.setTimeout( finish, 4000 );
		window.fetch( L.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( finish, finish );
	} );
}() );
