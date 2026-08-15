// auth_patch.go applies surgical modifications to the runtime-downloaded
// gowa-ui dashboard when multi-user authentication is enabled:
//
//  1. Removes the Server URL field from the login form so users always
//     authenticate against the same origin they loaded the page from.
//  2. Forces the login probe to use window.location.origin so the stored
//     baseUrl stays truthy (same-origin URLs survive page reloads).
//  3. Injects a self-contained register form (button + modal) that calls
//     POST /auth/register and, on success, writes the dashboard's zustand
//     localStorage state so the SPA boots straight into a connected session.
//  4. Restricts the axios logout trigger to genuine credential failures
//     (code UNAUTHORIZED) instead of every HTTP 401, so a temporarily
//     disconnected WhatsApp device (SERVICE_UNAVAILABLE) no longer kicks the
//     user back to the login page.
//
// The patch is applied at serve time (never to the cached file) and degrades
// gracefully: if any marker string no longer matches an updated dashboard
// build, the untouched content is served instead of a broken hybrid.
package uiasset

import "strings"

// authPatchMarker strings must match the minified gowa-ui bundle exactly.
// When upstream changes the bundle, the corresponding patch no-ops.
const (
	// serverURLField is the login form's Server URL <div> (unique via the
	// server-url id).
	serverURLField = `(0,I.jsxs)(` + "`" + `div` + "`" + `,{className:` + "`" + `flex flex-col gap-2` + "`" + `,children:[(0,I.jsx)(Q,{htmlFor:` + "`" + `server-url` + "`" + `,children:` + "`" + `Server URL` + "`" + `}),(0,I.jsx)($,{id:` + "`" + `server-url` + "`" + `,placeholder:` + "`" + `http://localhost:3000` + "`" + `,value:a,onChange:e=>o(e.target.value),required:!0})]}),`

	// loginSubmit is the login form's submit expression reading the (now
	// removed) server URL state variable.
	loginSubmit = "let n=await i(a,s||void 0,l||void 0);"

	// loginSubmitOrigin forces the login probe to the page's own origin.
	loginSubmitOrigin = "let n=await i(window.location.origin,s||void 0,l||void 0);"

	// responseInterceptor is the axios response interceptor that logs the user
	// out on ANY 401. gowa-ui marks the session as unauthorized on every 401,
	// but non-auth endpoints also legitimately return 401-shaped errors (see
	// the SERVICE_UNAVAILABLE mapping in pkg/error for the WhatsApp
	// disconnected state). Only the auth middleware's UNAUTHORIZED code must
	// trigger the logout.
	responseInterceptor     = "let t=HT(e);return t.status===401&&eE.getState().markUnauthorized(),Promise.reject(t)"
	responseInterceptorKeep = "let t=HT(e);return t.status===401&&t.code===`UNAUTHORIZED`&&eE.getState().markUnauthorized(),Promise.reject(t)"

	// headerCopy is the login card subtitle that references the server URL.
	headerCopy = "The server URL and optional basic-auth credentials are stored in this browser only."

	// headerCopyPatched is the replacement subtitle.
	headerCopyPatched = "Your credentials are stored in this browser only."
)

const authUIInjection = `<style>
#gowa-register-btn{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:60;border:1px solid var(--border);border-radius:9999px;padding:8px 18px;font:inherit;font-size:13px;cursor:pointer;color:var(--foreground);background:var(--card);box-shadow:0 4px 16px rgba(0,0,0,.15)}
#gowa-register-modal{position:fixed;inset:0;z-index:100;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.55);padding:16px}
#gowa-register-modal.open{display:flex}
#gowa-register-modal .gowa-register-card{width:100%;max-width:400px;background:var(--card);color:var(--foreground);border:1px solid var(--border);border-radius:16px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
#gowa-register-modal h3{margin:0 0 4px;font-size:18px;font-weight:600}
#gowa-register-modal .gowa-register-sub{margin:0 0 16px;font-size:13px;color:var(--muted-foreground)}
#gowa-register-modal label{display:block;margin:12px 0 4px;font-size:13px}
#gowa-register-modal input{width:100%;box-sizing:border-box;padding:8px 12px;border-radius:8px;border:1px solid var(--border);background:var(--input);color:var(--foreground);font:inherit;font-size:14px}
#gowa-register-modal input:focus{outline:2px solid var(--ring);outline-offset:1px}
#gowa-register-modal .gowa-register-error{margin:10px 0 0;font-size:13px;color:var(--destructive)}
#gowa-register-modal .gowa-register-actions{display:flex;gap:8px;margin-top:18px}
#gowa-register-modal button{cursor:pointer;font:inherit;font-size:14px;border-radius:8px;padding:8px 16px}
#gowa-register-modal .gowa-register-submit{border:1px solid transparent;background:var(--primary);color:var(--primary-foreground);flex:1}
#gowa-register-modal .gowa-register-close{border:1px solid var(--border);background:transparent;color:var(--foreground)}
</style>
<script>
(function(){
  var KEY='gowa-ui.connection.v1',ORIGIN=window.location.origin;
  var btn=document.createElement('button');
  btn.type='button';
  btn.id='gowa-register-btn';
  btn.textContent='No account? Register';
  var modal=document.createElement('div');
  modal.id='gowa-register-modal';
  modal.setAttribute('role','dialog');
  modal.setAttribute('aria-modal','true');
  modal.innerHTML='<div class="gowa-register-card"><h3>Create account</h3><p class="gowa-register-sub">Register with your email and a password.</p><form id="gowa-register-form"><label for="gowa-register-email">Email</label><input id="gowa-register-email" type="email" required autocomplete="email" placeholder="you@example.com"><label for="gowa-register-password">Password</label><input id="gowa-register-password" type="password" required minlength="6" maxlength="72" autocomplete="new-password" placeholder="At least 6 characters"><p class="gowa-register-error" id="gowa-register-error"></p><div class="gowa-register-actions"><button type="button" class="gowa-register-close" id="gowa-register-close">Cancel</button><button type="submit" class="gowa-register-submit" id="gowa-register-submit">Register</button></div></form></div>';
  function syncVisibility(){btn.style.display=document.getElementById('username')?'':'none'}
  function close(){modal.classList.remove('open')}
  btn.addEventListener('click',function(){modal.classList.add('open');var e=document.getElementById('gowa-register-email');if(e)e.focus()});
  modal.addEventListener('click',function(ev){if(ev.target===modal)close()});
  modal.querySelector('#gowa-register-close').addEventListener('click',close);
  modal.querySelector('#gowa-register-form').addEventListener('submit',async function(ev){
    ev.preventDefault();
    var err=document.getElementById('gowa-register-error');
    var email=document.getElementById('gowa-register-email').value.trim();
    var pass=document.getElementById('gowa-register-password').value;
    var submit=document.getElementById('gowa-register-submit');
    err.textContent='';
    submit.disabled=true;
    try{
      var res=await fetch(ORIGIN+'/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email,password:pass})});
      var data=null;
      try{data=await res.json()}catch(_){}
      if(!res.ok||!data||data.code!=='SUCCESS'){err.textContent=(data&&data.message)?data.message:('Registration failed ('+res.status+')');return}
      try{localStorage.setItem(KEY,JSON.stringify({state:{baseUrl:ORIGIN,username:email,password:pass},version:0}))}catch(_){}
      window.location.reload();
    }catch(_){err.textContent='Could not reach the server.'}
    finally{submit.disabled=false}
  });
  document.body.appendChild(btn);
  document.body.appendChild(modal);
  if(window.MutationObserver){new MutationObserver(syncVisibility).observe(document.body,{childList:true,subtree:true})}
  syncVisibility();
})();
</script>
</body>`

// ApplyAuthUIPatch rewrites the served dashboard HTML for the multi-user
// login/register flow. Each replacement is independent: unmatched markers
// (a newer dashboard build) are left untouched.
func ApplyAuthUIPatch(content []byte) []byte {
	if len(content) == 0 {
		return content
	}
	patched := strings.ReplaceAll(string(content), serverURLField, "")
	patched = strings.ReplaceAll(patched, loginSubmit, loginSubmitOrigin)
	patched = strings.ReplaceAll(patched, responseInterceptor, responseInterceptorKeep)
	patched = strings.ReplaceAll(patched, headerCopy, headerCopyPatched)
	patched = strings.ReplaceAll(patched, "</body>", authUIInjection)
	return []byte(patched)
}