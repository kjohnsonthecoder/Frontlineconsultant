import http from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {randomUUID,timingSafeEqual} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {scan,hostname,VERSION} from './scan.mjs';
import {scoreAssessment} from './model.mjs';
export function createService({token,allowedHosts,dbPath,scanImpl=scan,retentionDays=7}){
 if(!token||token.length<32||!allowedHosts?.length||allowedHosts.some(h=>!hostname(h)))throw new Error('Secure token and exact allowed hosts required');
 const db=new DatabaseSync(dbPath);db.exec(`PRAGMA journal_mode=WAL; PRAGMA secure_delete=ON; CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, principal TEXT, request_id TEXT, key TEXT, input TEXT, state TEXT, created INTEGER, output TEXT, UNIQUE(principal,key), UNIQUE(request_id)); CREATE TABLE IF NOT EXISTS audit(at INTEGER,event TEXT,job TEXT);`);
 db.prepare("UPDATE jobs SET state='failed',output=? WHERE state IN ('queued','running')").run(JSON.stringify({error:'Worker interrupted; staff investigation required',code:'WORKER_INTERRUPTED'}));
 const audit=(event,id)=>db.prepare('INSERT INTO audit VALUES(?,?,?)').run(Date.now(),event,id);
 const purge=()=>{const t=Date.now()-retentionDays*86400000;db.prepare("UPDATE jobs SET state='deleted',output=NULL WHERE created<? AND state NOT IN ('queued','running','deleted')").run(t);db.prepare('DELETE FROM audit WHERE at<?').run(t);};purge();
 const timer=setInterval(purge,3600000);timer.unref();let active=false;
 function view(row){return {assessment_id:row.id,request_id:row.request_id,target:JSON.parse(row.input).target,status:row.state,created_at:new Date(row.created).toISOString(),scanner_version:VERSION,...JSON.parse(row.output||'{}')};}
 async function work(row){active=true;db.prepare("UPDATE jobs SET state='running' WHERE id=?").run(row.id);const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),25000);
  try{const observations=await scanImpl(JSON.parse(row.input),controller.signal);const generated_at=new Date().toISOString();const result=scoreAssessment(observations.checks);const report={report_id:row.id,request_id:row.request_id,domain:JSON.parse(row.input).target,generated_at,sample:false,scanner_version:VERSION,report_version:'frontline-report-v1.0.0',scope:'Exact authorized hostname; DNS TXT, trusted TLS on 443, HTTP/HTTPS root only',result,findings:result.checks.filter(c=>c.status!=='pass').map(c=>({id:c.id,status:c.status,title:c.label,priority:'Review',severity:c.status==='fail'?'Low':'Unknown',evidence:c.evidence,observed_at:c.observed_at,impact:'Observed external configuration only; no exploitability conclusion.',action:'Review this observation with the domain administrator; validate mail flows and web compatibility before changing configuration.'})),notes:['DMARC organizational fallback, DKIM selectors, CSP meta policies, and exhaustive cipher-suite enumeration remain outside V1 coverage. Certificate expiry, hostname validation, chain trust, and deprecated TLS protocol support are assessed.'],limitations:result.limitations,evidence:{addresses:observations.addresses,tls:observations.tls}};
   db.prepare("UPDATE jobs SET state='completed',output=? WHERE id=?").run(JSON.stringify({result:report,completed_at:generated_at}),row.id);audit('completed',row.id);
  }catch(e){db.prepare("UPDATE jobs SET state='failed',output=? WHERE id=?").run(JSON.stringify({error:'Bounded scan could not complete',code:controller.signal.aborted?'SCAN_TIMEOUT':['DNS_OR_SCOPE_BLOCKED'].includes(e.message)?e.message:'SCAN_FAILED'}),row.id);audit('failed',row.id);}finally{clearTimeout(timeout);active=false;}
 }
 const server=http.createServer({maxHeaderSize:8192},async(req,res)=>{
  const reply=(status,data)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data));};
  try{
   if(req.method==='GET'&&req.url==='/health'){db.prepare('SELECT 1').get();return reply(200,{status:'ok'});}
   const supplied=String(req.headers.authorization||'');const expected='Bearer '+token;const a=Buffer.from(supplied),b=Buffer.from(expected);
   if(a.length!==b.length||!timingSafeEqual(a,b))return reply(401,{error:'Authentication required',code:'UNAUTHORIZED'});
   const principal=req.headers['x-frontline-principal'];if(typeof principal!=='string'||!/^[a-zA-Z0-9_-]{1,128}$/.test(principal)||req.headers['x-frontline-role']!=='admin')return reply(403,{error:'Staff principal required',code:'FORBIDDEN'});
   if(req.method==='GET'&&req.url==='/v1/health')return reply(200,{status:'ok',scanner_version:VERSION,report_version:'frontline-report-v1.0.0',ready:true});
   if(req.method==='POST'&&req.url==='/v1/assessments'){
    let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>4096)return reply(413,{error:'Request too large',code:'BODY_LIMIT'});}let input;try{input=JSON.parse(raw);}catch{return reply(400,{error:'Invalid JSON',code:'INVALID_JSON'});}
    const key=req.headers['idempotency-key'];const requestId=req.headers['x-frontline-request-id'];
    if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(k=>!['target','email_domain','authorization_confirmed'].includes(k))||!hostname(input.target)||input.authorization_confirmed!==true||!allowedHosts.includes(input.target)||(input.email_domain!=null&&input.email_domain!==input.target))return reply(403,{error:'Exact authorized host required',code:'SCOPE_DENIED'});
    if(!/^[a-zA-Z0-9_-]{16,128}$/.test(key||'')||!/^[a-f0-9]{24}$/.test(requestId||''))return reply(400,{error:'Valid request ID and idempotency key required',code:'INVALID_REQUEST_ID'});
    input={target:input.target,email_domain:input.email_domain||null,authorization_confirmed:true};const encoded=JSON.stringify(input);
    db.exec('BEGIN IMMEDIATE');let row;
    try{row=db.prepare('SELECT * FROM jobs WHERE (principal=? AND key=?) OR request_id=?').get(principal,key,requestId);if(row){db.exec('COMMIT');if(row.principal!==principal||row.key!==key||row.request_id!==requestId||row.input!==encoded)return reply(409,{error:'Request scope or owner conflicts with original',code:'IDEMPOTENCY_CONFLICT'});if(row.state==='deleted')return reply(410,{error:'Assessment deleted; this request cannot be rescanned',code:'JOB_DELETED'});return reply(200,view(row));}
     if(active||db.prepare('SELECT count(*) AS n FROM jobs WHERE created>?').get(Date.now()-86400000).n>=20){db.exec('COMMIT');return reply(429,{error:'Scanner capacity limit; retry same key later',code:'CAPACITY_LIMIT'});}
     row={id:randomUUID(),principal,request_id:requestId,key,input:encoded,state:'queued',created:Date.now(),output:null};db.prepare('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)').run(row.id,principal,requestId,key,encoded,'queued',row.created,null);db.exec('COMMIT');
    }catch(e){db.exec('ROLLBACK');throw e;}
    audit('accepted',row.id);reply(202,view(row));void work(row);return;
   }
   const match=/^\/v1\/assessments\/([a-f0-9-]{36})$/.exec(req.url||'');if(match&&['GET','DELETE'].includes(req.method)){
    const row=db.prepare('SELECT * FROM jobs WHERE id=? AND principal=?').get(match[1],principal);if(!row||row.state==='deleted')return reply(404,{error:'Assessment unavailable',code:'NOT_FOUND'});
    if(req.method==='DELETE'){if(['queued','running'].includes(row.state))return reply(409,{error:'Assessment is active',code:'ACTIVE_JOB'});db.prepare("UPDATE jobs SET state='deleted',output=NULL WHERE id=?").run(row.id);audit('deleted',row.id);return reply(200,{deleted:true});}return reply(200,view(row));
   }reply(404,{error:'Endpoint unavailable',code:'NOT_FOUND'});
  }catch{reply(500,{error:'Scanner internal error',code:'INTERNAL_ERROR'});}
 });
 server.setTimeout(10000,socket=>socket.destroy());server.requestTimeout=10000;server.headersTimeout=10000;server.maxHeadersCount=30;server.on('close',()=>{clearInterval(timer);db.close();});return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const server=createService({token:process.env.FRONTLINE_API_TOKEN,allowedHosts:(process.env.FRONTLINE_ALLOWED_HOSTS||'').split(',').filter(Boolean),dbPath:process.env.FRONTLINE_DB_PATH||'/data/frontline.sqlite'});server.listen(Number(process.env.PORT||8080),'0.0.0.0',()=>console.log('Frontline scanner started; secrets redacted'));}


