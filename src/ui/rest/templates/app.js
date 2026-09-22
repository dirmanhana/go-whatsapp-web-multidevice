/* Shared helpers for /admin and /account.
   Both pages are standalone documents served outside the gowa-ui bundle, so
   they re-read the session the dashboard persists in localStorage and replay
   it as an Authorization header. Two shapes are supported: a Bearer token
   (API clients) and the dashboard's Basic credentials. The server accepts
   either, and every admin/owner rule is re-checked there — this file only
   decides what to render. */
(function () {
	var STORE_KEY = 'gowa-ui.connection.v1';
	// Replaced at render time with config.AppBasePath ("" by default).
	var BASE = '{{BASE_PATH}}';

	function readState() {
		try {
			var raw = localStorage.getItem(STORE_KEY);
			if (!raw) return null;
			var parsed = JSON.parse(raw);
			var state = (parsed && parsed.state) || parsed || {};
			if (state.token) return state;
			if (state.username && state.password) return state;
			return null;
		} catch (e) {
			return null;
		}
	}

	function authHeaders(state) {
		if (state.token) return { Authorization: 'Bearer ' + state.token };
		return { Authorization: 'Basic ' + btoa(state.username + ':' + state.password) };
	}

	function goHome() {
		window.location.href = BASE + '/';
	}

	// api performs an authenticated JSON call and unwraps the server's
	// ResponseData envelope, throwing an Error carrying the server message.
	async function api(path, options) {
		options = options || {};
		var state = readState();
		if (!state) {
			goHome();
			var signedOut = new Error('Not signed in');
			signedOut.code = 'NOT_SIGNED_IN';
			throw signedOut;
		}
		var headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {}, authHeaders(state));
		var res = await fetch(BASE + path, Object.assign({}, options, { headers: headers }));
		var data = null;
		try { data = await res.json(); } catch (e) { /* non-JSON body */ }
		if (res.status === 401) {
			// Stale credentials: drop them and bounce to the dashboard login.
			localStorage.removeItem(STORE_KEY);
			goHome();
			var expired = new Error('Session expired');
			expired.code = 'UNAUTHORIZED';
			expired.status = 401;
			throw expired;
		}
		if (!res.ok || !data || data.code !== 'SUCCESS') {
			var message = data && data.message ? data.message : 'Request failed (' + res.status + ')';
			var err = new Error(message);
			err.code = (data && data.code) || 'HTTP_' + res.status;
			err.status = res.status;
			throw err;
		}
		return data.results;
	}

	function esc(value) {
		return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, function (c) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
		});
	}

	// showMessage renders a transient banner inside a target element.
	function showMessage(target, message, kind) {
		if (!target) return;
		if (!message) {
			target.classList.add('hidden');
			target.textContent = '';
			return;
		}
		target.textContent = message;
		target.classList.remove('hidden');
		target.classList.toggle('error', kind !== 'ok');
		target.classList.toggle('notice', kind === 'ok');
	}

	// updateStoredLogin patches the saved sign-in the dashboard replays on
	// every request (its Basic credentials). Token-only sessions are left
	// alone: their credential lives server-side and cannot be edited here.
	function updateStoredLogin(patch) {
		try {
			var raw = localStorage.getItem(STORE_KEY);
			if (!raw) return;
			var parsed = JSON.parse(raw);
			var state = (parsed && parsed.state) || parsed;
			if (!state || state.token) return;
			if (patch.username && typeof patch.username === 'string') state.username = patch.username;
			if (patch.password && typeof patch.password === 'string') state.password = patch.password;
			localStorage.setItem(STORE_KEY, JSON.stringify(parsed));
		} catch (e) {
			/* a broken blob just means the next call re-authenticates */
		}
	}

	window.GOWA = {
		BASE: BASE,
		api: api,
		esc: esc,
		readState: readState,
		showMessage: showMessage,
		updateStoredLogin: updateStoredLogin,
		goHome: goHome
	};
})();
