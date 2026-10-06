import test from 'node:test';
import assert from 'node:assert/strict';
import {createBridge} from './base44-bridge.mjs';
test('Base44 health verifies readiness and start carries saved request ID',async()=>{
 let network=0,healthOK=true;const record={id:'6ac2e5f23f27e08217e5f34e',domain:'frontlineconsultant.com',status:'authorized',authorization_reference:'test authorization',authorized_by:'staff',authorized_at:'2026-10-04T23:49:39Z',authorization_acknowledged:true,permission_to_contact:true};
 const bridge=createBridge({getUser:async()=>({id:'staff',role:'admin'}),apiUrl:'https://scanner.invalid',apiToken:'x'.repeat(48),getRequest:async()=>record,updateRequest:async(_r,_id,data)=>Object.assign(record,data),fetchImpl:async(url,options)=>{network++;if(url.pathname==='/v1/health')return Response.json({status:healthOK?'ok':'error',ready:healthOK});assert.equal(options.headers['X-Frontline-Request-ID'],record.id);assert.equal(JSON.parse(options.body).target,record.domain);return Response.json({assessment_id:'00000000-0000-0000-0000-000000000001',status:'queued'},{status:202});}});
 const call=body=>bridge(new Request('https://base44.invalid',{method:'POST',body:JSON.stringify(body)}));
 assert.equal((await (await call({action:'status'})).json()).connected,true);assert.equal(network,1);assert.equal(record.assessment_id,undefined);
 healthOK=false;assert.equal((await (await call({action:'status'})).json()).configured,false);
 const input={action:'start',request_id:record.id,target:record.domain,email_domain:null,authorization_confirmed:true,idempotency_key:'test-key-12345678'};
 assert.equal((await call({...input,target:'other.com'})).status,403);
 assert.equal((await call(input)).status,202);assert.equal(record.status,'submitted');assert.equal(record.scan_key,input.idempotency_key);
 const before=network;assert.equal((await call(input)).status,200);assert.equal(network,before);
});
