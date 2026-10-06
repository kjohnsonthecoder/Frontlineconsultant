import {Resolver} from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
export const VERSION='frontline-v1.0.1';
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
 const req=(secure?https:http).request({hostname:host,port:secure?443:80,path:'/',method:'GET',agent:false,servername:host,signal,timeout:5000,lookup:(_h,_o,cb)=>cb(null,ip,4),headers:{'User-Agent':'Frontline-V1/1.0 (authorized root-page posture check)','Accept':'text/html','Accept-Encoding':'identity'}},res=>{
 let bytes=0;res.on('data',chunk=>{bytes+=chunk.length;if(bytes>65536)res.destroy();});
 const sock=res.socket;resolve({status:res.statusCode,headers:res.headers,tls:secure?{protocol:sock.getProtocol(),cipher:sock.getCipher(),certificate:sock.getPeerCertificate(),authorized:sock.authorized}:null});
 // No page content is retained, no links followed, no cookies replayed.
 res.on('error',()=>{});
 });req.on('timeout',()=>req.destroy(new Error('NETWORK_TIMEOUT')));req.on('error',reject);req.end();
 });}
export async function scan(input,signal){
 const resolver=new Resolver({timeout:2000,tries:1});signal.addEventListener('abort',()=>resolver.cancel(),{once:true});
 const checks=[];const add=(id,status,evidence,confidence='high')=>checks.push({id,status,evidence,confidence,observed_at:new Date().toISOString()});
 let addresses;try{addresses=await resolver.resolve4(input.target);if(!addresses.length||addresses.some(a=>!publicIP(a)))throw new Error('UNSAFE_ADDRESS');}catch{throw new Error('DNS_OR_SCOPE_BLOCKED');}
 if(signal.aborted)throw new Error('SCAN_TIMEOUT');
 const ip=addresses[0];let web;
 try{web=await request(input.target,ip,true,signal);add('https',web.status>=200&&web.status<400?'pass':'partial',`HTTPS root returned ${web.status}; pinned public address ${ip}`);add('certificate','pass',`Trusted hostname-validated certificate; expires ${web.tls.certificate.valid_to}; TLS ${web.tls.protocol}; cipher ${web.tls.cipher.name}; SHA256 ${web.tls.certificate.fingerprint256}`);}
 catch(e){add('https','unknown','HTTPS root unavailable; no availability conclusion','low');add('certificate',e.code==='CERT_HAS_EXPIRED'||e.code==='ERR_TLS_CERT_ALTNAME_INVALID'||e.code==='DEPTH_ZERO_SELF_SIGNED_CERT'?'fail':'unknown',e.code||'TLS observation unavailable',e.code?'medium':'low');}
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


