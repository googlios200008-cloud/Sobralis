'use strict';
// Same-origin frontend/API gateway. It listens on loopback only and is NOT a
// TLS terminator; a separately configured HTTPS reverse proxy must be in front.
// No demo credentials, bearer bridge, diagnostics, or user-supplied upstream.
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),{Transform}=require('node:stream');
const ROOT=path.resolve(__dirname,'..');
const files=new Map([
  ['/','index.html'],['/index.html','index.html'],['/cloud.html','cloud.html'],
  ['/verify-email','registration.html'],['/reset-password','recovery.html'],
  ...['style.css','shared.css','cloud.css','app.js','enhancements.js','party.js','backup.js','family.js','shared.js','trip-ui.js','host-ui.js','cloud.js','manifest.webmanifest','hero-web.webp','hero.png','registration.html','registration.js','registration.css','recovery.html','recovery.js','assets/icon-192.png','assets/icon-512.png','assets/nunito-cyrillic.woff2','assets/nunito-latin.woff2'].map(x=>['/'+x,x])
]);
const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.webmanifest':'application/manifest+json; charset=utf-8','.png':'image/png','.webp':'image/webp','.woff2':'font/woff2'};
const csp="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'self'";
// Standalone account pages also avoid inline styles; the main shell still
// needs them for its legacy dynamic layout. Inline scripts are forbidden everywhere.
const strictCsp=csp.replace("style-src 'self' 'unsafe-inline'","style-src 'self'");
function validateOrigin(value){try{const u=new URL(value);return u.protocol==='https:'&&u.origin===value&&!u.username&&!u.password&&!u.pathname.slice(1)&&!u.search&&!u.hash?u:null}catch{return null}}
function cleanHeaders(input){const out={...input},connection=String(out.connection||'').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean);for(const name of [...connection,'connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade'])delete out[name];return out}
function createGateway({publicOrigin,apiPort}){
  const origin=validateOrigin(publicOrigin);if(!origin)throw Error('PUBLIC_ORIGIN must be an exact HTTPS origin');
  if(!Number.isInteger(apiPort)||apiPort<1||apiPort>65535)throw Error('Invalid API port');
  const server=http.createServer((req,res)=>{
    res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');
    if(req.headers.host!==origin.host){res.writeHead(421);res.end();return}
    // Do not allow absolute URLs, authority-form, or slash/backslash ambiguity.
    if(!req.url||!req.url.startsWith('/')||req.url.startsWith('//')||req.url.includes('\\')||/[\x00-\x1f\x7f]/.test(req.url)){res.writeHead(400);res.end();return}
    let url;try{url=new URL(req.url,publicOrigin)}catch{res.writeHead(400);res.end();return}
    if(url.origin!==publicOrigin){res.writeHead(400);res.end();return}
    if(url.pathname.startsWith('/api/')){
      if(!['GET','POST','PUT','PATCH','DELETE'].includes(req.method)){res.writeHead(405,{Allow:'GET, POST, PUT, PATCH, DELETE'});res.end();return}
      const h=cleanHeaders(req.headers);for(const k of Object.keys(h))if(k==='forwarded'||k==='x-real-ip'||k==='x-demo-session'||k.startsWith('x-forwarded-'))delete h[k];h.host=origin.host;
      // Enforce the backend’s 16 KiB limit even for chunked requests.
      if(h['content-length']&&(!/^\d+$/.test(h['content-length'])||Number(h['content-length'])>16384)){res.writeHead(413);res.end();req.resume();return}
      const upstream=http.request({host:'127.0.0.1',port:apiPort,path:req.url,method:req.method,headers:h},r=>{
        res.writeHead(r.statusCode||502,cleanHeaders(r.headers));r.pipe(res);
      });
      upstream.setTimeout(12000,()=>upstream.destroy());
      upstream.on('error',()=>{if(!res.headersSent){res.writeHead(503,{'Content-Type':'application/json; charset=utf-8'});res.end('{"error":"UNAVAILABLE"}')}else if(!res.writableEnded)res.destroy()});
      let received=0;const limiter=new Transform({transform(chunk,_encoding,done){received+=chunk.length;done(received>16384?new Error('body limit'):null,received>16384?undefined:chunk)}});
      limiter.on('error',()=>{req.unpipe(limiter);if(!res.headersSent){res.writeHead(413);res.end()}else if(!res.writableEnded)res.destroy();upstream.destroy();req.resume()});
      req.on('aborted',()=>{limiter.destroy();upstream.destroy()});req.pipe(limiter).pipe(upstream);return;
    }
    if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405,{Allow:'GET, HEAD'});res.end();return}
    const name=files.get(url.pathname);if(!name){res.writeHead(404);res.end();return}
    if(name.endsWith('.html'))res.setHeader('Content-Security-Policy',name==='index.html'?csp:strictCsp);
    res.setHeader('Content-Type',types[path.extname(name)]||'application/octet-stream');
    if(req.method==='HEAD'){res.writeHead(200);res.end();return}
    fs.createReadStream(path.join(ROOT,name)).on('error',()=>{if(!res.headersSent){res.writeHead(503);res.end()}else res.destroy()}).pipe(res);
  });
  server.headersTimeout=10000;server.requestTimeout=15000;server.keepAliveTimeout=5000;
  server.on('clientError',(_err,socket)=>{if(socket.writable)socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')});
  server.on('connect',(_req,socket)=>socket.destroy());server.on('upgrade',(_req,socket)=>socket.destroy());
  return server;
}
if(require.main===module){
  const port=Number(process.env.GATEWAY_PORT||4180),apiPort=Number(process.env.API_PORT||8080);
  if(!Number.isInteger(port)||port<1||port>65535)throw Error('Invalid gateway port');
  const server=createGateway({publicOrigin:process.env.PUBLIC_ORIGIN,apiPort});server.listen(port,'127.0.0.1',()=>console.log('Frontend gateway listening on loopback'));
}
module.exports={createGateway,validateOrigin};
