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
//  5. Adds the features this server hosts itself to the dashboard's own
//     sidebar menu, matching the app's navigation style: an "Account
//     settings" item opening /account (every signed-in user) and a "Users"
//     item opening /admin that only appears when GET /auth/me reports
//     is_admin. The admin flag is enforced server-side regardless — the item
//     merely keeps the navigation honest.
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

// authUIInjection adds the register entry point on the login card. It appears
// on every view; the button itself is only visible while the login form is on
// screen (the username input only exists there).
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
</script>`

// authEntryInjection adds the two server-hosted pages to the dashboard's own
// sidebar. The menu mirrors the group markup the app renders from its lD
// array (uppercase group label + NavLink rows), but uses plain <a> anchors:
// the SPA router only knows its own routes, so /account and /admin must force
// a full page load to reach the pages this server serves. A MutationObserver
// re-applies the group whenever React re-renders the nav (route changes,
// drawer mounts), and the admin item's visibility is driven by GET /auth/me.
// __GOWA_BASE__ is replaced with config.AppBasePath at serve time.
const authEntryInjection = `<script>
(function(){
  // Reconciles with the dashboard's own sidebar: label group (uppercase,
  // tracked wide) plus rounded-full NavLink rows, as rendered by uD/lD in the
  // minified bundle. Anchors navigate with a full page load on purpose.
  var BASE='__GOWA_BASE__';
  var ICON_ACCOUNT='<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="5"/><path d="M20 21a8 8 0 0 0-16 0"/></svg>';
  var ICON_USERS='<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>';
  var STORE='gowa-ui.connection.v1';
  function navs(){
    var out=[];
    document.querySelectorAll('nav').forEach(function(n){
      var c=n.classList;
      if(c.contains('flex')&&c.contains('flex-col')&&c.contains('gap-4'))out.push(n);
    });
    return out;
  }
  function authHeaders(){
    try{
      var raw=localStorage.getItem(STORE);if(!raw)return null;
      var p=JSON.parse(raw),s=(p&&p.state)||p||{};
      if(s.token)return{Authorization:'Bearer '+s.token};
      if(s.username&&s.password)return{Authorization:'Basic '+btoa(s.username+':'+s.password)};
    }catch(e){}
    return null;
  }
  var adminState=null,checkedAt=0;
  async function isAdmin(){
    var now=Date.now();
    if(adminState!==null&&now-checkedAt<60000)return adminState;
    var h=authHeaders();
    if(!h){adminState=false;checkedAt=now;return false}
    try{
      var res=await fetch(window.location.origin+'/auth/me',{headers:h});
      var data=res.ok?await res.json():null;
      adminState=!!(data&&data.results&&data.results.is_admin);
    }catch(e){adminState=false}
    checkedAt=now;
    return adminState;
  }
  function syncAdmin(){
    isAdmin().then(function(ok){
      document.querySelectorAll('[data-gowa-admin]').forEach(function(el){el.style.display=ok?'':'none'});
    });
  }
  function makeGroup(){
    var g=document.createElement('div');
    g.className='flex flex-col gap-1';
    g.setAttribute('data-gowa-menu','1');
    var p=document.createElement('p');
    p.className='text-muted-foreground px-3 text-[11px] font-medium tracking-wider uppercase';
    p.textContent='Account';
    g.appendChild(p);
    function row(href,label,icon,admin){
      var a=document.createElement('a');
      a.href=BASE+href;
      a.className='flex items-center gap-2.5 rounded-full px-3 py-2 text-sm font-medium transition-colors text-muted-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground';
      var ic=document.createElement('span');
      ic.className='size-4 shrink-0';
      ic.innerHTML=icon;
      var tx=document.createElement('span');
      tx.textContent=label;
      a.appendChild(ic);
      a.appendChild(tx);
      if(admin){a.setAttribute('data-gowa-admin','1')}
      return a;
    }
    g.appendChild(row('/account','Account settings',ICON_ACCOUNT,false));
    g.appendChild(row('/admin','Users',ICON_USERS,true));
    return g;
  }
  function inject(){
    var changed=false;
    navs().forEach(function(nav){
      if(nav.querySelector('[data-gowa-menu]'))return;
      nav.appendChild(makeGroup());
      changed=true;
    });
    if(adminState===null)syncAdmin();
  }
  inject();
  if(window.MutationObserver){
    var pending=null;
    new MutationObserver(function(){
      if(pending)return;
      pending=setTimeout(function(){pending=null;inject()},250);
    }).observe(document.body,{childList:true,subtree:true});
  }
  setInterval(syncAdmin,60000);
})();
</script>`

// ApplyAuthUIPatch rewrites the served dashboard HTML for the multi-user
// login/register flow. Each replacement is independent: unmatched markers
// (a newer dashboard build) are left untouched. basePath is config.AppBasePath
// and is baked into the injected navigation so deep links survive a non-empty
// base path.
func ApplyAuthUIPatch(content []byte, basePath string) []byte {
	if len(content) == 0 {
		return content
	}
	patched := strings.ReplaceAll(string(content), serverURLField, "")
	patched = strings.ReplaceAll(patched, loginSubmit, loginSubmitOrigin)
	patched = strings.ReplaceAll(patched, responseInterceptor, responseInterceptorKeep)
	patched = strings.ReplaceAll(patched, headerCopy, headerCopyPatched)
	entry := strings.ReplaceAll(authEntryInjection, "__GOWA_BASE__", basePath)
	patched = strings.ReplaceAll(patched, "</body>", authUIInjection+entry)
	return []byte(patched)
}
