import test from 'node:test';
import assert from 'node:assert/strict';
import {createService} from './server.mjs';
import {hostname,publicIP,redirectAllowed,redirectEvidence} from './scan.mjs';
import {scoreAssessment} from './model.mjs';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
test('Exact scope and public-address protections',()=>{
 for(const h of ['127.0.0.1','https://frontlineconsultant.com','frontlineconsultant.com:443','Frontlineconsultant.com','a..com','localhost'])assert.equal(hostname(h),false);
 assert.equal(hostname('frontlineconsultant.com'),true);
 for(const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','100.64.0.1','172.16.0.1','192.168.1.1','::1','::ffff:127.0.0.1','198.18.0.1'])assert.equal(publicIP(ip),false);
 assert.equal(publicIP('8.8.8.8'),true);
 assert.equal(redirectAllowed('https://frontlineconsultant.com/','frontlineconsultant.com'),true);
 for(const u of ['https://www.frontlineconsultant.com/','https://frontlineconsultant.com/login','https://frontlineconsultant.com/?a=1','https://u:p@frontlineconsultant.com/'])assert.equal(redirectAllowed(u,'frontlineconsultant.com'),false);
});
test('API authentication, principal ownership, durable-key rules, report and deletion',async()=>{
 let calls=0;const server=createService({token:'x'.repeat(48),allowedHosts:['frontlineconsultant.com'],dbPath:':memory:',scanImpl:async()=>{calls++;return {checks:[],addresses:['8.8.8.8'],tls:null};}});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const url=`http://127.0.0.1:${server.address().port}`;
 const headers={Authorization:'Bearer '+'x'.repeat(48),'X-Frontline-Principal':'staff','X-Frontline-Role':'admin','Idempotency-Key':'test-idempotency-123456','X-Frontline-Request-ID':'6ac2e5f23f27e08217e5f34e','Content-Type':'application/json'};
 const input={target:'frontlineconsultant.com',email_domain:null,authorization_confirmed:true};
 const post=(body=input,h=headers)=>fetch(url+'/v1/assessments',{method:'POST',headers:h,body:JSON.stringify(body)});
 try{
  const health=await fetch(url+'/health');assert.equal(health.status,200);assert.deepEqual(await health.json(),{status:'ok'});assert.equal(calls,0);
  assert.equal((await fetch(url+'/v1/assessments')).status,401);
  assert.equal((await fetch(url+'/v1/health')).status,401);
  assert.equal((await fetch(url+'/v1/health',{headers})).status,200);assert.equal(calls,0);
  assert.equal((await post({...input,target:'other.com'})).status,403);
  assert.equal((await post({...input,email_domain:'other.com'})).status,403);
  assert.equal((await post({...input,authorization_confirmed:false})).status,403);
  assert.equal((await post(input,{...headers,'X-Frontline-Request-ID':''})).status,400);
  const first=await post();assert.equal(first.status,202);const job=await first.json();assert.equal(calls,1);
  const replay=await post();assert.equal(replay.status,200);assert.equal((await replay.json()).assessment_id,job.assessment_id);assert.equal(calls,1);
  assert.equal((await post({...input,email_domain:input.target})).status,409);
  assert.equal((await post(input,{...headers,'Idempotency-Key':'another-key-123456'})).status,409);
  const path=url+'/v1/assessments/'+job.assessment_id;
  assert.equal((await fetch(path,{headers:{...headers,'X-Frontline-Principal':'other'}})).status,404);
  const completed=await (await fetch(path,{headers})).json();assert.equal(completed.status,'completed');assert.equal(completed.result.sample,false);assert.equal(completed.result.result.score,null);
  assert.equal((await fetch(path,{method:'DELETE',headers})).status,200);assert.equal((await fetch(path,{headers})).status,404);
  assert.equal((await post()).status,410);assert.equal(calls,1);
 }finally{await new Promise(r=>server.close(r));}
});
test('Redirect evidence never retains credentials, query values, paths or unrelated hosts',()=>{
 const evidence=redirectEvidence('https://user:secret@other.example/private?token=secret','frontlineconsultant.com');
 assert.equal(evidence.includes('secret'),false);assert.equal(evidence.includes('private'),false);assert.equal(evidence.includes('other.example'),false);
 assert.match(evidence,/credentials=true/);
});
test('Single worker capacity, active deletion and pending state',async()=>{
 let finish;const pending=new Promise(r=>finish=r);
 const s=createService({token:'q'.repeat(48),allowedHosts:['frontlineconsultant.com'],dbPath:':memory:',scanImpl:async()=>{await pending;return {checks:[],addresses:[],tls:null};}});
 await new Promise(r=>s.listen(0,'127.0.0.1',r));const base=`http://127.0.0.1:${s.address().port}`;
 const headers={Authorization:'Bearer '+'q'.repeat(48),'X-Frontline-Principal':'staff','X-Frontline-Role':'admin','Idempotency-Key':'pending-key-123456','X-Frontline-Request-ID':'6ac2e5f23f27e08217e5f34e'};
 const body=JSON.stringify({target:'frontlineconsultant.com',authorization_confirmed:true});
 try{
  const first=await (await fetch(base+'/v1/assessments',{method:'POST',headers,body})).json();
  const path=base+'/v1/assessments/'+first.assessment_id;
  assert.equal((await (await fetch(path,{headers})).json()).status,'running');
  assert.equal((await fetch(path,{method:'DELETE',headers})).status,409);
  assert.equal((await fetch(base+'/v1/assessments',{method:'POST',headers:{...headers,'Idempotency-Key':'second-key-123456','X-Frontline-Request-ID':'6ac2e5f23f27e08217e5f34f'},body})).status,429);
 }finally{finish();await new Promise(r=>s.close(r));}
});
test('Unknown evidence suppresses score',()=>{assert.equal(scoreAssessment([]).score,null);});
test('Restart preserves idempotency and failure never silently rescans',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'frontline-test-'));let calls=0;
 const config={token:'z'.repeat(48),allowedHosts:['frontlineconsultant.com'],dbPath:join(dir,'test.sqlite'),scanImpl:async()=>{calls++;throw new Error('DNS_OR_SCOPE_BLOCKED');}};
 const headers={Authorization:'Bearer '+'z'.repeat(48),'X-Frontline-Principal':'staff','X-Frontline-Role':'admin','Idempotency-Key':'durable-idempotency-123','X-Frontline-Request-ID':'6ac2e5f23f27e08217e5f34e'};
 const body=JSON.stringify({target:'frontlineconsultant.com',authorization_confirmed:true,email_domain:null});let original;
 try{for(let n=0;n<2;n++){const s=createService(config);await new Promise(r=>s.listen(0,'127.0.0.1',r));try{const base=`http://127.0.0.1:${s.address().port}`;const response=await fetch(base+'/v1/assessments',{method:'POST',headers,body});const row=await response.json();if(n===0)original=row.assessment_id;else assert.equal(row.assessment_id,original);const job=await (await fetch(base+'/v1/assessments/'+original,{headers})).json();assert.equal(job.status,'failed');assert.equal(job.code,'DNS_OR_SCOPE_BLOCKED');}finally{await new Promise(r=>s.close(r));}}assert.equal(calls,1);}finally{rmSync(dir,{recursive:true,force:true});}
});
