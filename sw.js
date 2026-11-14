const CACHE='acro-quality-shell-v1';
const SHELL=['/login','/static/manifest.webmanifest','/static/icon.svg'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL))));
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))));
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=='GET' || u.origin!==location.origin) return;
  // Do not cache authenticated pages or memo/company data.
  if(u.pathname.startsWith('/static/')) e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request)));
});
