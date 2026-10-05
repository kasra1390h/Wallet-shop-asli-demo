// Pure, side-effect-free helpers — extracted so they can be unit-tested with `node --test`
// without needing a database, network, or a running server.

function luhnOk(n){let s=0,alt=false;for(let i=n.length-1;i>=0;i--){let d=+n[i];if(alt){d*=2;if(d>9)d-=9}s+=d;alt=!alt}return s%10===0}

function magicOk(buf,mime){
 if(mime==='image/png')return buf.length>8&&buf[0]===0x89&&buf[1]===0x50&&buf[2]===0x4e&&buf[3]===0x47;
 if(mime==='image/jpeg')return buf.length>3&&buf[0]===0xff&&buf[1]===0xd8;
 return false}

// For custom-gift uploads: sniff the real file type from bytes, ignoring whatever the browser claims.
// Returns 'png' | 'jpeg' | 'gif' | 'webp' | null (unrecognized).
function sniffImage(buf){
 if(buf.length>8&&buf[0]===0x89&&buf[1]===0x50&&buf[2]===0x4e&&buf[3]===0x47)return'png';
 if(buf.length>3&&buf[0]===0xff&&buf[1]===0xd8)return'jpeg';
 if(buf.length>6&&buf.slice(0,3).toString('ascii')==='GIF')return'gif';
 if(buf.length>12&&buf.slice(0,4).toString('ascii')==='RIFF'&&buf.slice(8,12).toString('ascii')==='WEBP')return'webp';
 return null}

// Loose Lottie-JSON sanity check: valid JSON, object, and has at least one field real Lottie
// files always have ('v' version string, or a 'layers'/'assets' array). Rejects arbitrary JSON blobs.
function isValidLottieJson(buf){
 let j;try{j=JSON.parse(buf.toString('utf8'))}catch(e){return false}
 if(!j||typeof j!=='object'||Array.isArray(j))return false;
 return typeof j.v==='string'||Array.isArray(j.layers)||Array.isArray(j.assets)}

const RECIPIENT_RE=/^@?[a-zA-Z0-9_]{5,32}$/;
const recipientValid=s=>RECIPIENT_RE.test(String(s||'').trim());

// Order state machine: which transitions are allowed from each status.
const ORDER_TRANS={paid:['fulfilling','failed','refunded','cancelled'],fulfilling:['delivered','failed','refunded'],
 delivered:['refunded'],failed:['fulfilling','refunded'],refunded:[],cancelled:[]};
const canTransition=(from,to)=>(ORDER_TRANS[from]||[]).includes(to);

// Pure price calculation — same formula as server.js's price(), without touching the DB.
// Rounds the raw float to 6 decimals before ceiling, because JS float multiplication
// (e.g. 200*0.014*900000) can land a hair above a whole number (2520000.0000000005),
// which would otherwise silently overcharge the customer by 1 toman via Math.ceil.
function priceCalc(stars,qty,starUsd,rate,feePct){
 const raw=stars*qty*starUsd*rate,base=Math.ceil(Math.round(raw*1e6)/1e6);
 const rawFee=base*feePct/100,fee=Math.ceil(Math.round(rawFee*1e6)/1e6);
 return{base,fee,total:base+fee}}

function toCsv(rows){if(!rows.length)return'';const cols=Object.keys(rows[0]);
 const esc=v=>{v=v==null?'':String(v);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v};
 return cols.join(',')+'\n'+rows.map(r=>cols.map(c=>esc(r[c])).join(',')).join('\n')}

// ---- Role-based access control ----
// ADMIN_ROLES env format: "id:role,id:role" e.g. "111:super,222:finance,333:support,444:inventory,555:viewer"
// Any admin ID not listed there defaults to 'super' (keeps old ADMIN_IDS-only setups working unchanged).
const ROLE_PERMS={
 // topup.view: see the queue/receipts. topup.action: actually send a card / approve / reject (moves money).
 // order.view: see orders/dashboard. order.fulfill: move paid->fulfilling->delivered/failed (no money).
 // order.refund: credit money back (separate from fulfill — a support agent can mark things delivered
 // without being able to touch anyone's balance). settings: maintenance mode + feature flags.
 // rate.settings: fee %, star price, dollar rate (financial, but not maintenance/flags).
 super:    ['topup.view','topup.action','order.view','order.fulfill','order.refund','settings','rate.settings','users','audit','export','reconcile','gifts.manage'],
 finance:  ['topup.view','topup.action','order.view','order.refund','rate.settings','audit','export','reconcile'],
 support:  ['topup.view','order.view','order.fulfill','users'],
 inventory:['order.view','order.fulfill','gifts.manage'],
 viewer:   ['topup.view','order.view']
};
function parseAdminRoles(envStr,adminIds){
 const roles={};adminIds.forEach(id=>roles[id]='super'); // default
 String(envStr||'').split(',').map(s=>s.trim()).filter(Boolean).forEach(pair=>{
  const [id,role]=pair.split(':');const n=+id;
  if(adminIds.includes(n)&&ROLE_PERMS[role])roles[n]=role});
 return roles}
const roleHas=(role,perm)=>(ROLE_PERMS[role]||[]).includes(perm);

module.exports={luhnOk,magicOk,sniffImage,isValidLottieJson,recipientValid,RECIPIENT_RE,ORDER_TRANS,canTransition,priceCalc,toCsv,
 ROLE_PERMS,parseAdminRoles,roleHas};
