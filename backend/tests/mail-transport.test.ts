// Local synthetic SMTP over encrypted sockets; does not send external email.
import {test} from 'node:test';import assert from 'node:assert/strict';import net from 'node:net';import tls from 'node:tls';import {mkdtemp,readFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join,resolve} from 'node:path';import {spawn,execFileSync} from 'node:child_process';

test('SMTP implicit TLS and STARTTLS use authenticated encrypted channels and verify certificates', {timeout:35000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'sobralis-smtp-test-'));let server:net.Server|tls.Server|null=null;const sockets=new Set<net.Socket>(),received:string[]=[];let unencryptedAuth=false,noStartTLS=false;
 try{
  const key=join(dir,'key.pem'),cert=join(dir,'cert.pem');execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',key,'-out',cert],{stdio:'ignore'});
  const material={key:await readFile(key),cert:await readFile(cert)},context=tls.createSecureContext(material);
  function protocol(socket:net.Socket,encrypted:boolean){
   sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{});
   let pending='',inData=false,data='',authStep=0;
   socket.on('data',chunk=>{pending+=chunk.toString('utf8');for(;;){const n=pending.indexOf('\r\n');if(n<0)break;const line=pending.slice(0,n);pending=pending.slice(n+2);
    if(inData){if(line==='.') {received.push(data);data='';inData=false;socket.write('250 queued\r\n')}else data+=line+'\n';continue}
    if(authStep){if(!encrypted)unencryptedAuth=true;if(authStep===1){authStep=2;socket.write('334 UGFzc3dvcmQ6\r\n')}else{authStep=0;socket.write('235 2.7.0 accepted\r\n')}continue}
    if(/^EHLO /i.test(line)){socket.write(encrypted?'250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1000000\r\n':(noStartTLS?'250-localhost\r\n250 SIZE 1000000\r\n':'250-localhost\r\n250-STARTTLS\r\n250 SIZE 1000000\r\n'));continue}
    if(/^STARTTLS$/i.test(line)&&!encrypted){if(noStartTLS){socket.write('454 TLS unavailable\r\n');continue}socket.removeAllListeners('data');socket.write('220 ready for TLS\r\n',()=>{const wrapped=new tls.TLSSocket(socket,{isServer:true,secureContext:context});wrapped.on('error',()=>{});protocol(wrapped,true)});break}
    if(/^AUTH PLAIN/i.test(line)){if(!encrypted)unencryptedAuth=true;socket.write('235 2.7.0 accepted\r\n');continue}
    if(/^AUTH LOGIN/i.test(line)){if(!encrypted)unencryptedAuth=true;authStep=1;socket.write('334 VXNlcm5hbWU6\r\n');continue}
    if(/^MAIL FROM:/i.test(line)||/^RCPT TO:/i.test(line)){socket.write('250 ok\r\n');continue}
    if(/^DATA$/i.test(line)){inData=true;socket.write('354 send data\r\n');continue}
    if(/^QUIT$/i.test(line)){socket.end('221 goodbye\r\n');continue}
    socket.write('250 ok\r\n');
   }});
  }
  async function run(mode:'implicit'|'starttls',trusted:boolean,downgrade=false){
   noStartTLS=downgrade;server=mode==='implicit'?tls.createServer(material,s=>{protocol(s,true);s.write('220 localhost ESMTP\r\n')}):net.createServer(s=>{protocol(s,false);s.write('220 localhost ESMTP\r\n')});server.on('tlsClientError',()=>{});await new Promise<void>(r=>server!.listen(0,'127.0.0.1',r));const port=(server.address() as net.AddressInfo).port;
   const env={...process.env,EMAIL_MODE:'smtp',SMTP_HOST:'127.0.0.1',SMTP_PORT:String(port),SMTP_TLS_MODE:mode,SMTP_USER:'synthetic',SMTP_PASSWORD:'synthetic-password',SMTP_FROM:'no-reply@example.test',EXPECT_REJECT:trusted&&!downgrade?'no':'yes'};delete env.NODE_EXTRA_CA_CERTS;if(trusted)env.NODE_EXTRA_CA_CERTS=cert;
   const child=spawn(process.execPath,['--import','tsx',resolve('tests/helpers/smtp-client.ts')],{env,stdio:'ignore'});const code=await new Promise<number|null>((ok,bad)=>{child.on('error',bad);child.on('exit',ok)});assert.equal(code,0,`synthetic ${mode} child failed`);
   for(const s of sockets)s.destroy();await new Promise<void>(r=>server!.close(()=>r()));server=null;
  }
  await run('implicit',false);await run('starttls',false);await run('starttls',true,true);assert.equal(received.length,0);await run('implicit',true);await run('starttls',true);
  assert.equal(received.length,4);assert.equal(unencryptedAuth,false);const decoded=received.map(raw=>{const split=raw.indexOf('\n\n'),head=raw.slice(0,split),body=raw.slice(split+2);return /content-transfer-encoding:\s*base64/i.test(head)?Buffer.from(body.replace(/\s/g,''),'base64').toString('utf8'):body.replace(/=\n/g,'').replace(/=([0-9A-F]{2})/gi,(_m,h)=>String.fromCharCode(parseInt(h,16)))});assert.equal(decoded.filter(x=>x.includes('/verify-email#')).length,2);assert.equal(decoded.filter(x=>x.includes('/reset-password#')).length,2);
 }finally{for(const s of sockets)s.destroy();if(server)await new Promise<void>(r=>server!.close(()=>r()));await rm(dir,{recursive:true,force:true})}
});
