/** Frontline Exposure Risk Index. FERI-0.1, provisional policy model. */
export const MODEL = Object.freeze({
  version: 'FERI-0.1', minimumCoverage: 80,
  checks: [
    {id:'https', category:'Transport', label:'HTTPS availability', weight:15},
    {id:'certificate', category:'Transport', label:'Certificate validity', weight:15},
    {id:'redirect', category:'Transport', label:'HTTP to HTTPS redirect', weight:5},
    {id:'spf', category:'Email', label:'SPF policy configuration', weight:15},
    {id:'dmarc', category:'Email', label:'DMARC policy configuration', weight:20},
    {id:'hsts', category:'Browser', label:'HSTS', weight:10},
    {id:'csp', category:'Browser', label:'Content Security Policy', weight:10},
    {id:'framing', category:'Browser', label:'Framing restrictions', weight:5},
    {id:'nosniff', category:'Browser', label:'MIME sniffing protection', weight:5},
    // V1.1 TLS detail controls are scored by FERI-0.2 in Base44. They are accepted
    // here with zero legacy weight so the scanner's provisional FERI-0.1 remains stable.
    {id:'tls_cert_expiry', category:'Transport', label:'Certificate expiry window', weight:0},
    {id:'tls_hostname_match', category:'Transport', label:'Certificate hostname match', weight:0},
    {id:'tls_chain_trust', category:'Transport', label:'Certificate chain and trust', weight:0},
    {id:'tls_deprecated_protocols', category:'Transport', label:'Deprecated TLS protocol support', weight:0},
  ]
});
const VALUES = {pass:0, partial:0.5, fail:1};
export function band(score) {
  if (score === null) return 'Insufficient evidence';
  return score < 15 ? 'Low observed risk' : score < 35 ? 'Guarded' : score < 60 ? 'Elevated' : score < 80 ? 'High' : 'Very high';
}
export function scoreAssessment(input) {
  if (!Array.isArray(input)) throw new Error('Checks must be an array');
  const ids = new Set();
  for (const c of input) {
    if (!MODEL.checks.some(m => m.id === c.id) || ids.has(c.id)) throw new Error('Unknown or duplicate check');
    if (!['pass','partial','fail','unknown','not_applicable'].includes(c.status)) throw new Error('Invalid status');
    if (!['high','medium','low'].includes(c.confidence)) throw new Error('Invalid confidence');
    if (c.status !== 'unknown' && (!c.evidence?.trim() || !c.observed_at || !Number.isFinite(Date.parse(c.observed_at)))) throw new Error('Evidence and valid timestamp required');
    if (c.status === 'not_applicable' && !c.justification?.trim()) throw new Error('Exclusion requires justification');
    ids.add(c.id);
  }
  const checks = MODEL.checks.map(m => {
    const c = input.find(c => c.id === m.id) || {id:m.id,status:'unknown',confidence:'low',evidence:'Not collected'};
    const status = c.confidence === 'low' ? 'unknown' : c.status;
    return {...c, ...m, status, points: (VALUES[status] ?? 0) * m.weight};
  });
  const applicable = checks.filter(c => c.status !== 'not_applicable');
  const observed = applicable.filter(c => Object.hasOwn(VALUES,c.status));
  const totalWeight = applicable.reduce((n,c)=>n+c.weight,0);
  const observedWeight = observed.reduce((n,c)=>n+c.weight,0);
  const points = observed.reduce((n,c)=>n+c.points,0);
  const categories = ['Transport','Email','Browser'].map(name => {
    const all = applicable.filter(c=>c.category===name);
    const done = observed.filter(c=>c.category===name);
    const aw = all.reduce((n,c)=>n+c.weight,0), dw = done.reduce((n,c)=>n+c.weight,0);
    return {name,applicable_weight:aw,observed_weight:dw,coverage:aw ? Math.round(100*dw/aw) : null,
      risk:dw ? Math.round(100*done.reduce((n,c)=>n+c.points,0)/dw) : null};
  });
  const coverage = totalWeight ? Math.round(100*observedWeight/totalWeight) : 0;
  const publish = totalWeight > 0 && 100*observedWeight/totalWeight >= MODEL.minimumCoverage && categories.every(c=>c.applicable_weight===0 || c.observed_weight>0);
  const score = publish ? Math.round(100*points/observedWeight) : null;
  return {model:MODEL.version,score,band:band(score),coverage,
    risk_interval:totalWeight ? [Math.floor(100*points/totalWeight),Math.ceil(100*(points+totalWeight-observedWeight)/totalWeight)] : null,
    categories,checks,limitations:'External configuration index only. Not breach probability, CVSS, penetration testing, or compliance certification.'};
}


