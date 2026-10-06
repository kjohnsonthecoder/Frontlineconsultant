export function createBridge({getUser,apiUrl,apiToken,fetchImpl=fetch,getRequest,updateRequest}) {
  return async req=>{
    const reply=(data,status=200)=>Response.json(data,{status,headers:{'Cache-Control':'no-store'}});
    if(req.method!=='POST')return reply({error:'POST required'},405);
    let user;try{user=await getUser(req);}catch{return reply({error:'Sign in required'},401);}
    if(!user?.id)return reply({error:'Sign in required'},401);
    if(user.role!=='admin')return reply({error:'Frontline administrator access required'},403);
    let body;try{const raw=await req.text();if(new TextEncoder().encode(raw).length>4096)return reply({error:'Request too large'},413);body=JSON.parse(raw);}catch{return reply({error:'Invalid JSON'},400);}
    if(!body||typeof body!=='object'||Array.isArray(body))return reply({error:'Invalid action'},400);
    let validOrigin=false;try{const origin=new URL(apiUrl);validOrigin=origin.protocol==='https:'&&!origin.username&&!origin.password&&!origin.search&&!origin.hash&&origin.pathname==='/';}catch{/* missing origin */}
    const configured=Boolean(validOrigin&&apiToken&&apiToken.length>=32);
    if(body.action==='status'){
      if(!configured)return reply({configured:false,connected:false,staff_only:true});
      try{const health=await fetchImpl(new URL('/v1/health',apiUrl),{method:'GET',headers:{Authorization:'Bearer '+apiToken,'X-Frontline-Principal':user.id,'X-Frontline-Role':'admin'},redirect:'error',signal:AbortSignal.timeout(5000)});const raw=await health.text();if(raw.length>8192)throw new Error();const data=JSON.parse(raw);const connected=health.ok&&data.status==='ok'&&data.ready===true;return reply({configured:connected,secrets_present:true,connected,staff_only:true,scanner_version:connected?data.scanner_version:null});}catch{return reply({configured:false,secrets_present:true,connected:false,staff_only:true,code:'SCANNER_UNAVAILABLE'});}
    }
    if(!configured)return reply({error:'The cloud scanner has not been connected yet.',code:'SCANNER_NOT_CONFIGURED'},503);
    let base;try{base=new URL(apiUrl);if(base.protocol!=='https:'||base.username||base.password||base.search||base.hash||base.pathname!=='/')throw new Error();}catch{return reply({error:'Scanner configuration is invalid'},503);}
    const headers={Authorization:'Bearer '+apiToken,'X-Frontline-Principal':user.id,'X-Frontline-Role':'admin'};
    let path,options;
    if(body.action==='start'){
      if(Object.keys(body).some(k=>!['action','target','email_domain','authorization_confirmed','idempotency_key','request_id'].includes(k)))return reply({error:'Unsupported input'},400);
      if(body.authorization_confirmed!==true)return reply({error:'Confirm authorization before starting'},403);
      if(typeof body.idempotency_key!=='string'||!/^[a-zA-Z0-9_-]{16,128}$/.test(body.idempotency_key))return reply({error:'Invalid request key'},400);
      let record;
      try{record=await getRequest?.(req,body.request_id);}catch{return reply({error:'Authorized request could not be loaded'},403);}
      if(!record||!['authorized','submitted'].includes(record.status)||!record.authorization_reference?.trim()||!record.authorized_by||!record.authorized_at||record.authorization_acknowledged!==true||record.permission_to_contact!==true)return reply({error:'A verified staff authorization record is required'},403);
      if(body.target!==record.domain||(body.email_domain&&body.email_domain!==record.domain))return reply({error:'Target differs from the authorized hostname'},403);
      if(record.scan_key&&(record.scan_email_domain||null)!==(body.email_domain||null))return reply({error:'Email scope differs from the original request'},409);
      if(record.scan_key&&record.scan_key!==body.idempotency_key)return reply({error:'Reuse the original request key for this assessment'},409);
      if(record.assessment_id)return reply({assessment_id:record.assessment_id,target:record.domain,status:'queued'});
      try{await updateRequest(req,record.id,{scan_key:body.idempotency_key,scan_email_domain:body.email_domain||''});}catch{return reply({error:'Scan request could not be recorded'},503);}
      path='/v1/assessments';options={method:'POST',headers:{...headers,'Content-Type':'application/json','Idempotency-Key':body.idempotency_key,'X-Frontline-Request-ID':record.id},body:JSON.stringify({target:body.target,email_domain:body.email_domain||null,authorization_confirmed:true})};
    }else if(body.action==='get'){
      if(Object.keys(body).some(k=>!['action','assessment_id'].includes(k))||!(/^[a-f0-9-]{36}$/.test(body.assessment_id||'')))return reply({error:'Invalid assessment reference'},400);
      path='/v1/assessments/'+body.assessment_id;options={method:'GET',headers};
    }else return reply({error:'Unsupported action'},400);
    try{
      const response=await fetchImpl(new URL(path,base),{...options,redirect:'error',signal:AbortSignal.timeout(10000)});
      const text=await response.text();if(text.length>2*1024*1024)throw new Error('Oversized response');
      const data=JSON.parse(text);
      if(body.action==='start'&&response.ok&&data.assessment_id){try{await updateRequest(req,body.request_id,{assessment_id:data.assessment_id,status:'submitted'});}catch{return reply({error:'Scanner accepted the request, but the assessment link could not be saved. Retry with the same request key.',code:'REQUEST_LINK_PENDING'},502);}}
      return reply(data,response.status);
    }catch{return reply({error:'The scanner service could not be reached. Retry the request.',code:'SCANNER_UNAVAILABLE'},502);}
  };
}


