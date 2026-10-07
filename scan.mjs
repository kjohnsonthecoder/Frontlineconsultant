import {Resolver} from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
export const VERSION='frontline-v1.1.0';
export function pinnedLookup(ip){
 return (_host,options,callback)=>options?.all
  ?callback(null,[{address:ip,family:4}])
  :callback(null,ip,4);
}
// Retain configuration evidence without storing arbitrary server-supplied URLs or secrets.
export function redirectEvidence(location,host){
 if(!location)return 'absent';
 try{const u=new URL(location,`http://${host}/`);return `${u.protocol} host=${u.hostname===host?'authorized':'out-of-scope'} root=${u.pathname==='/'} query=${Boolean(u.search)} credentials=${Boolean(u.username||u.password)}`;}catch{return 'invalid URL';}
}
export function hostname(s){return typeof s==='string'&&s.length<=253&&s===s.toLowerCase()&&/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(s);}
export function publicIP(ip){
 if(net.isIP(ip)===4){const [a,b,c]=ip.split('.').map(Number);return !(a===0||a===10||a===127||a>=224||(a===100&&b>=64&&b<=127)||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&(b===168||b===0||b===2))||(a===192&&b===88&&c===99)||(a===198&&(b===18||b===19||b===51))||(a===203&&b===0&&c===113));}
 // V1 deliberately uses only public IPv4, avoiding IPv6 transition/embedded-address ambiguity.
 return false;
}
export function redirectAllowed(location,host){try{const u=new URL(location,`http://${host}/`);return u.protocol==='https:'&&u.hostname===host&&!u.username&&!u.password&&!u.port&&u.pathname==='/'&&!u.search&&!u.hash;}catch{return false;}}
async function request(host,ip,secure,signal){return new Promise((resolve,reject)=>{
 const req=(secure?https:http).request({hostname:host,port:secure?443:80,path:'/',method:'GET',agent:false,servername:host,signal,timeout:5000,lookup:pinnedLookup(ip),headers:{'User-Agent':'Frontline-V1/1.1 (authorized root-page posture check)','Accept':'text/html','Accept-Encoding':'identity'}},res=>{
 let bytes=0;res.on('data',chunk=>{bytes+=chunk.length;if(bytes>65536)res.destroy();});
 const sock=res.socket;resolve({status:res.statusCode,headers:res.headers,tls:secure?{protocol:sock.getProtocol(),cipher:sock.getCipher(),certificate:sock.getPeerCertificate(true),authorized:sock.authorized,authorizationError:sock.authorizationError||null}:null});
 // No page content is retained, no links followed, no cookies replayed.
 res.on('error',()=>{});
 });req.on('timeout',()=>req.destroy(new Error('NETWORK_TIMEOUT')));req.on('error',reject);req.end();
 });}
export function daysUntil(dateString,now=Date.now()){
 const t=Date.parse(dateString||'');return Number.isFinite(t)?Math.floor((t-now)/86400000):null;
}
export function certificateChainDepth(cert){
 let depth=0,current=cert,seen=new Set();
 while(current&&current.raw&&depth<10){
  const fp=current.fingerprint256||current.serialNumber||String(depth);
  if(seen.has(fp))break;seen.add(fp);depth++;
  if(!current.issuerCertificate||current.issuerCertificate===current)break;
  current=current.issuerCertificate;
 }
 return depth;
}
export function deprecatedProtocolResult(results){
 if(results.some(r=>r.supported===true))return {status:'fail',evidence:'Deprecated TLS protocol accepted: '+results.filter(r=>r.supported===true).map(r=>r.version).join(', ')};
 if(results.every(r=>r.supported===false))return {status:'pass',evidence:'TLS 1.0 and TLS 1.1 were not accepted by the authorized endpoint'};
 return {status:'unknown',evidence:'Deprecated TLS protocol support could not be determined conclusively'};
}
async function probeTlsVersion(host,ip,version,signal){return new Promise(resolve=>{
 let settled=false;
 const finish=(value)=>{if(settled)return;settled=true;resolve(value);};
 let socket;
 try{
  socket=tls.connect({host:ip,port:443,servername:host,minVersion:version,maxVersion:version,rejectUnauthorized:false,timeout:3500},()=>{socket.destroy();finish({version,supported:true});});
  const abort=()=>{socket.destroy();finish({version,supported:null});};signal.addEventListener('abort',abort,{once:true});
  socket.on('timeout',()=>{socket.destroy();finish({version,supported:null});});
  socket.on('error',e=>{
   const msg=String(e?.message||'');
   const rejected=/protocol version|unsupported protocol|wrong version number|no protocols available|alert protocol|tlsv1 alert/i.test(msg)||['ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION','ERR_SSL_UNSUPPORTED_PROTOCOL','ERR_SSL_NO_PROTOCOLS_AVAILABLE'].includes(e?.code);
   finish({version,supported:rejected?false:null});
  });
 }catch{finish({version,supported:null});}
 });}
export async function scan(input,signal){
 const resolver=new Resolver({timeout:2000,tries:1});signal.addEventListener('abort',()=>resolver.cancel(),{once:true});
 const checks=[];const add=(id,status,evidence,confidence='high')=>checks.push({id,status,evidence,confidence,observed_at:new Date().toISOString()});
 let addresses;try{addresses=await resolver.resolve4(input.target);if(!addresses.length||addresses.some(a=>!publicIP(a)))throw new Error('UNSAFE_ADDRESS');}catch{throw new Error('DNS_OR_SCOPE_BLOCKED');}
 if(signal.aborted)throw new Error('SCAN_TIMEOUT');
 const ip=addresses[0];let web;
 try{
  web=await request(input.target,ip,true,signal);
  add('https',web.status>=200&&web.status<400?'pass':'partial',`HTTPS root returned ${web.status}; pinned public address ${ip}`);
  add('certificate','pass',`Trusted hostname-validated certificate; expires ${web.tls.certificate.valid_to}; TLS ${web.tls.protocol}; cipher ${web.tls.cipher.name}; SHA256 ${web.tls.certificate.fingerprint256}`);
  const remaining=daysUntil(web.tls.certificate.valid_to);
  add('tls_cert_expiry',remaining==null?'unknown':remaining<0?'fail':remaining<30?'partial':'pass',remaining==null?'Certificate expiration date could not be parsed':`Certificate expires in ${remaining} day(s); observed expiry ${web.tls.certificate.valid_to}`,remaining==null?'low':'high');
  add('tls_hostname_match','pass','TLS connection completed with hostname verification for the approved target');
  add('tls_chain_trust',web.tls.authorized?'pass':'fail',web.tls.authorized?`Certificate chain validated; observed chain depth ${certificateChainDepth(web.tls.certificate)}`:`Certificate chain was not authorized: ${web.tls.authorizationError||'unknown trust error'}`);
 }catch(e){
  add('https','unknown','HTTPS root unavailable; no availability conclusion','low');
  const certFail=['CERT_HAS_EXPIRED','ERR_TLS_CERT_ALTNAME_INVALID','DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_VERIFY_LEAF_SIGNATURE','SELF_SIGNED_CERT_IN_CHAIN'].includes(e.code);
  add('certificate',certFail?'fail':'unknown',e.code||'TLS observation unavailable',e.code?'medium':'low');
  add('tls_cert_expiry',e.code==='CERT_HAS_EXPIRED'?'fail':'unknown',e.code==='CERT_HAS_EXPIRED'?'Presented certificate is expired':'Certificate expiry could not be observed','medium');
  add('tls_hostname_match',e.code==='ERR_TLS_CERT_ALTNAME_INVALID'?'fail':'unknown',e.code==='ERR_TLS_CERT_ALTNAME_INVALID'?'Presented certificate does not match the approved hostname':'Certificate hostname match could not be confirmed','medium');
  add('tls_chain_trust',['DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_VERIFY_LEAF_SIGNATURE','SELF_SIGNED_CERT_IN_CHAIN'].includes(e.code)?'fail':'unknown',e.code||'Certificate chain trust could not be confirmed',e.code?'medium':'low');
 }
 const deprecated=deprecatedProtocolResult(await Promise.all([probeTlsVersion(input.target,ip,'TLSv1',signal),probeTlsVersion(input.target,ip,'TLSv1.1',signal)]));
 add('tls_deprecated_protocols',deprecated.status,deprecated.evidence,deprecated.status==='unknown'?'low':'high');
 try{const r=await request(input.target,ip,false,signal);add('redirect',r.status>=300&&r.status<400&&redirectAllowed(r.headers.location,input.target)?'pass':'fail',`HTTP root status ${r.status}; Location ${redirectEvidence(r.headers.location,input.target)}; redirects never followed`);}catch{add('redirect','unknown','HTTP root unavailable','low');}
 for(const id of ['hsts','csp','framing','nosniff']){
  if(!web||web.status!==200){add(id,'unknown','No successful HTTPS root response','low');continue;}
  const h=web.headers;let value,status;
  if(id==='hsts'){value=h['strict-transport-security'];status=/max-age\s*=\s*[1-9]\d*/i.test(value||'')?'pass':value?'partial':'fail';}
  if(id==='csp'){value=h['content-security-policy'];status=value?'partial':'unknown';}
  if(id==='framing'){value=h['x-frame-options']||h['content-security-policy'];status=/^(deny|sameorigin)$/i.test(h['x-frame-options']||'')||/frame-ancestors\s+(?:'none'|'self')(?:\s*;|$)/i.test(h['content-security-policy']||'')?'pass':value?'partial':'fail';}
  if(id==='nosniff'){value=h['x-content-type-options'];status=String(value).toLowerCase()==='nosniff'?'pass':'fail';}
  add(id,status,`${id} response header: ${value?'present (value omitted for data minimization)':'absent'}${id==='csp'?'; header presence only; meta policies and policy effectiveness not assessed':''}`,status==='unknown'?'low':'medium');
 }
 for(const id of ['spf','dmarc']){
  if(!input.email_domain){add(id,'unknown','Actual sending domain not confirmed','low');continue;}
  try{const name=id==='spf'?input.target:`_dmarc.${input.target}`;let txt;try{txt=(await resolver.resolveTxt(name)).map(r=>r.join(''));}catch(e){if(['ENODATA','ENOTFOUND'].includes(e.code))txt=[];else throw e;}
   const policies=txt.filter(t=>id==='spf'?/^v=spf1(?:\s|$)/i.test(t):/^v=DMARC1\s*;/i.test(t));
   // Do not follow SPF include/redirect or organizational-domain fallback: those are separate hosts.
   const status=policies.length===0||policies.length>1?'fail':'partial';
   add(id,status,`${name} TXT: ${policies.length+' exact-host policy record(s); raw values omitted'}; configuration discovery only; syntax, SPF lookup expansion, DKIM alignment and organizational fallback not assessed`,'medium');
  }catch{add(id,'unknown','DNS TXT query unavailable','low');}
 }
 if(signal.aborted)throw new Error('SCAN_TIMEOUT');
 return {checks,addresses,tls:web?.tls?{protocol:web.tls.protocol,cipher:web.tls.cipher.name}:null};
}


