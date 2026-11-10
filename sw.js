self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
// Avisos chegam criptografados: só este aparelho tem a chave (guardada no IndexedDB, não exportável)
const idb=()=>new Promise((res,rej)=>{const r=indexedDB.open('hrc',1);r.onupgradeneeded=()=>r.result.createObjectStore('k');r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)});
async function openC(c){const db=await idb();const k=await new Promise((res,rej)=>{const q=db.transaction('k').objectStore('k').get('n');q.onsuccess=()=>res(q.result);q.onerror=()=>rej(q.error)});if(!k)throw new Error('sem chave');
  const u=Uint8Array.from(atob(c),x=>x.charCodeAt(0));return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:u.slice(0,12)},k,u.slice(12))))}
self.addEventListener('push',e=>e.waitUntil((async()=>{let d={};try{d=e.data.json()}catch(x){d={body:e.data?e.data.text():''}}let t=d.title,b=d.body;
  if(d.c){try{const o=await openC(d.c);t=o.t;b=o.b}catch(x){t='Habit RC';b='Você tem um aviso. Abra o app.'}}
  await self.registration.showNotification(String(t||'Habit RC').slice(0,80),{body:String(b||'Hora de pilotar!').slice(0,200),icon:'icon.png',tag:String(d.tag||'gt3').slice(0,40)})})()));
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>l.length?l[0].focus():self.clients.openWindow('./')))});
