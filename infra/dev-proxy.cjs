// Disposable demo only. No TLS, authentication, audit or isolation of its own.
// Terminate HTTPS at a trusted preview proxy; never use this server in production.
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),allowed=new Map([['/',process.env.DEMO_START==='cloud'?'cloud.html':'index.html'],['/verify-email','registration.html'],['/reset-password','recovery.html'],...['index.html','style.css','app.js','enhancements.js','party.js','backup.js','family.js','manifest.webmanifest','assets/icon-192.png','assets/icon-512.png','hero.png','hero-web.webp','cloud.html','cloud.css','cloud.js','registration.html','registration.js','registration.css','recovery.html','recovery.js','trip-ui.js','host-ui.js','shared.css','shared.js','assets/nunito-cyrillic.woff2','assets/nunito-latin.woff2'].map(x=>['/'+x,x])]);
const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.png':'image/png','.webp':'image/webp','.woff2':'font/woff2','.webmanifest':'application/manifest+json; charset=utf-8'};
const publicOrigin=process.env.PUBLIC_ORIGIN;if(!publicOrigin)throw Error('PUBLIC_ORIGIN required');const host=new URL(publicOrigin).host;
const port=Number(process.env.PREVIEW_PORT||4175),apiPort=Number(process.env.API_PORT||8081);
// This explicitly opt-in bridge is ONLY for the disposable, publicly shared demo.
// The browser holds an opaque bearer in memory; the backend cookie stays on this proxy.
// Refresh or proxy restart signs the demo tab out. Production auth is untouched.
const bridge=process.env.DEMO_SESSION_BRIDGE==='yes';
if(bridge&&(process.env.NODE_ENV!=='development'||process.env.DB_NAME!=='sobralis_demo'||!['cloud','original'].includes(process.env.DEMO_START)))throw Error('Session bridge only allowed for disposable demo');
const inline=process.env.DEMO_INLINE==='yes',autoLogin=process.env.DEMO_AUTO_LOGIN==='yes';
const opaqueFrame=process.env.DEMO_OPAQUE_IFRAME==='yes';
if(opaqueFrame&&(!bridge||!inline||process.env.DEMO_QUICK_LOGIN!=='yes'))throw Error('Opaque-origin exception is only for the disposable inline bridged demo');
if((inline||autoLogin)&&(!bridge||process.env.DEMO_QUICK_LOGIN!=='yes'))throw Error('Inline or automatic login only allowed in disposable bridged demo');
const demoConfig={quickLogin:process.env.DEMO_QUICK_LOGIN==='yes',memorySession:bridge,autoLogin};
const sessions=new Map(),ttl=60*60*1000,capacity=500;
function expire(){const t=Date.now();for(const [id,s] of sessions)if(s.expires<=t)sessions.delete(id)}
http.createServer((req,res)=>{
  if(req.headers.host!==host){if(process.env.DEMO_DIAGNOSTICS==='yes')console.log('Demo request rejected: unexpected Host');res.writeHead(421);res.end();return}
  res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Content-Type-Options','nosniff');
  const pathname=new URL(req.url,publicOrigin).pathname;
  if(pathname==='/demo-config'&&req.method==='GET'&&process.env.DEMO_QUICK_LOGIN==='yes'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify(demoConfig));return}
  if(pathname.startsWith('/api/')){
    // Opaque sandboxed preview frames send Origin: null. The opt-in exception
    // applies ONLY to the public synthetic demo bearer bridge, never normal API
    // traffic. Nothing stored here is suitable for real users or personal data.
    const sandboxRequest=opaqueFrame&&req.headers.origin==='null';
    if(sandboxRequest){
      res.setHeader('Access-Control-Allow-Origin','null');
      res.setHeader('Access-Control-Expose-Headers','X-Demo-Session');
      res.setHeader('Vary','Origin');
      if(req.method==='OPTIONS'){
        const method=(req.headers['access-control-request-method']||'').toUpperCase();
        const requested=(req.headers['access-control-request-headers']||'').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean);
        if(!['GET','POST','PUT','PATCH','DELETE'].includes(method)||requested.some(h=>!['content-type','x-csrf-token','x-demo-session'].includes(h))){res.writeHead(403);res.end();return}
        res.writeHead(204,{'Access-Control-Allow-Methods':'GET, POST, PUT, PATCH, DELETE','Access-Control-Allow-Headers':'Content-Type, X-CSRF-Token, X-Demo-Session','Access-Control-Max-Age':'300'});res.end();return;
      }
    }
    const headers={...req.headers};if(sandboxRequest)headers.origin=publicOrigin;delete headers['x-forwarded-for'];delete headers['x-forwarded-host'];delete headers['x-forwarded-proto'];
    let key;if(bridge){expire();key=typeof headers['x-demo-session']==='string'&&/^[A-Za-z0-9_-]{43}$/.test(headers['x-demo-session'])?headers['x-demo-session']:null;delete headers['x-demo-session'];delete headers.cookie;if(key&&sessions.has(key))headers.cookie=sessions.get(key).cookie}
    const upstream=http.request({hostname:'127.0.0.1',port:apiPort,path:req.url,method:req.method,headers},r=>{
      const resultHeaders={...r.headers};
      if(bridge){
        delete resultHeaders['set-cookie'];
        if(pathname==='/api/auth/login'&&req.method==='POST'&&r.statusCode===200){
          const cookie=(r.headers['set-cookie']||[]).map(x=>x.split(';')[0]).find(x=>/^__Host-sobralis_session=[A-Za-z0-9_-]{43}$/.test(x));
          if(!cookie||sessions.size>=capacity){r.resume();res.writeHead(503,{'content-type':'application/json','cache-control':'no-store'});res.end('{"error":"DEMO_SESSION_UNAVAILABLE"}');return}
          if(key)sessions.delete(key);const id=crypto.randomBytes(32).toString('base64url');sessions.set(id,{cookie,expires:Date.now()+ttl});resultHeaders['x-demo-session']=id;
        }
        if(pathname==='/api/auth/logout'&&req.method==='POST'&&r.statusCode===200&&key)sessions.delete(key);
      }
      if(process.env.DEMO_DIAGNOSTICS==='yes' && (pathname==='/api/auth/login'||pathname==='/api/auth/me'))console.log(`Demo auth ${pathname.endsWith('/login')?'login':'session'}: status=${r.statusCode} originMatches=${req.headers.origin===publicOrigin} demoSession=${Boolean(key&&sessions.has(key))} json=${/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||'')}`);
      res.writeHead(r.statusCode,resultHeaders);r.pipe(res);
    });
    upstream.on('error',()=>{if(!res.headersSent)res.writeHead(503,{'content-type':'application/json','cache-control':'no-store'});res.end('{"error":"UNAVAILABLE"}')});req.pipe(upstream);return;
  }
  if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405);res.end();return}
  const file=allowed.get(pathname);if(!file){res.writeHead(404);res.end();return}
  // Demo HTML still needs inline handlers/scripts; this is a restrictive safety net, not XSS protection.
  if(file.endsWith('.html'))res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-src 'none'");
  res.setHeader('Content-Type',types[path.extname(file)]||'application/octet-stream');if(req.method==='HEAD'){res.end();return}
  if(inline&&file==='index.html'){
    try{let html=fs.readFileSync(path.join(root,'index.html'),'utf8'),css=fs.readFileSync(path.join(root,'style.css'),'utf8')+'\n'+fs.readFileSync(path.join(root,'shared.css'),'utf8');
      if(/<\/style/i.test(css))throw Error('Unexpected closing tag');
      for(const [asset,mime] of [['hero-web.webp','image/webp'],['assets/nunito-cyrillic.woff2','font/woff2'],['assets/nunito-latin.woff2','font/woff2']]){const data=fs.readFileSync(path.join(root,asset)).toString('base64');if(asset==='hero-web.webp'){css=css.split(`url('${asset}')`).join('var(--demo-hero)');css+=`\n:root{--demo-hero:url("data:${mime};base64,${data}")}`}else css=css.split(`url('${asset}')`).join(`url('data:${mime};base64,${data}')`)}
      const style='<link rel="stylesheet" href="style.css?v=7"><link rel="stylesheet" href="shared.css?v=4">';if(!html.includes(style))throw Error('Demo styles changed');html=html.replace(style,()=>`<style>${css}</style>`);
      const config={...demoConfig,autoLogin:demoConfig.autoLogin&&new URL(req.url,publicOrigin).searchParams.get('manual')!=='1'};
      let first=true;for(const [name,version] of [['app.js','12'],['enhancements.js','8'],['party.js','8'],['backup.js','10'],['shared.js','7'],['family.js','2'],['trip-ui.js','8'],['host-ui.js','2'],['cloud.js','18']]){const tag=`<script src="${name}?v=${version}"></script>`,js=fs.readFileSync(path.join(root,name),'utf8');if(!html.includes(tag)||/<\/script/i.test(js))throw Error('Demo scripts changed');const pre=first?`<script>window.__SOBRALIS_DEMO__=${JSON.stringify(config)};</script>`:'';first=false;html=html.replace(tag,()=>`${pre}<script>${js}</script>`)}
      res.end(html);
    }catch{res.writeHead(500);res.end('Demo page unavailable')};return;
  }
  if(inline&&file==='cloud.html'){
    try{let html=fs.readFileSync(path.join(root,'cloud.html'),'utf8');const css=fs.readFileSync(path.join(root,'cloud.css'),'utf8'),js=fs.readFileSync(path.join(root,'cloud.js'),'utf8'),tripJs=fs.readFileSync(path.join(root,'trip-ui.js'),'utf8'),hostJs=fs.readFileSync(path.join(root,'host-ui.js'),'utf8');
      // Reject unexpected closing tags rather than interpolating untrusted HTML.
      if(/<\/style/i.test(css)||/<\/script/i.test(js)||/<\/script/i.test(tripJs)||/<\/script/i.test(hostJs))throw Error('Unexpected closing tag');
      const stylesheet='<link rel="stylesheet" href="cloud.css?v=4">',script='<script src="cloud.js?v=18"></script>',tripScript='<script src="trip-ui.js?v=8"></script>',hostScript='<script src="host-ui.js?v=2"></script>';
      if(!html.includes(stylesheet)||!html.includes(script)||!html.includes(tripScript)||!html.includes(hostScript))throw Error('Demo HTML templates changed');
      const config={...demoConfig,autoLogin:demoConfig.autoLogin&&new URL(req.url,publicOrigin).searchParams.get('manual')!=='1'};
      html=html.replace(stylesheet,()=>`<style>${css}</style>`).replace(tripScript,()=>`<script>${tripJs}</script>`).replace(hostScript,()=>`<script>${hostJs}</script>`).replace(script,()=>`<script>window.__SOBRALIS_DEMO__=${JSON.stringify(config)};</script><script>${js}</script>`);res.end(html);
    }catch{res.writeHead(500);res.end('Demo page unavailable')};return;
  }
  fs.createReadStream(path.join(root,file)).on('error',()=>res.destroy()).pipe(res);
}).listen(port,'0.0.0.0',()=>console.log(`Disposable demo frontend listening on ${port}`));
