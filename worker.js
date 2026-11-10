// 灵宠空间 中转站（原型）：Cloudflare Worker + KV（绑定名 BOX；可选变量 ALLOW_ORIGINS，逗号分隔的网页来源，空 = 不限）
// 只存整封加密信件；信箱编号 = 灵宠指纹。无账号，全靠签名：
//  · 占座：收信人签名上传“允许名单”才开通信箱；座位总数有限；座位够用时随机 24~48 小时到期，吃紧（占用 ≥80%）时 6~12 小时；在线客户端剩余不足 4 小时自动续期
//  · 投信：验信件签名，寄信人须在收信人的名单里；每个信箱有数量配额；信件 ≤ MAX_LETTER
//  · 取信：先用 1 次读取比对信箱版本（etag），有新信才列表；客户端前台 8~30 秒轮询（KV 跨节点最长约 60 秒可见，为平台特性）
//  · 已读回执：读者签名上传“已读”的信件 id，存进寄信人的信箱（读者须在寄信人的允许名单里），寄信人取信时一并取走并确认删除
const TTL=7*86400, MAX_LETTER=300000, MAX_BODY=400000, MAX_ALLOW=200, MAX_TO=50, MAX_FETCH=20, MAX_RD=40, MAX_RESP=12e6, SKEW=5*60*1000;
const MAX_SEATS=100, SEAT_MIN_H=24, SEAT_MAX_H=48, TIGHT_MIN_H=6, TIGHT_MAX_H=12, TIGHT_RATIO=0.8, RENEW_LEFT_H=4, SETTLE_MS=90e3, MAX_BOX_N=30, MAX_ADD_CHANGES=10, MAX_SEATS_PER_IP=10; // MAX_SEATS / MAX_SEATS_PER_IP 可用同名环境变量覆盖
const num=(v,d)=>Number.isFinite(+v)&&+v>0?+v:d;
const ID_RE=/^id_[0-9a-f]{32}$/;
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET, POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'86400'};
const reply=(s,st=200)=>new Response(typeof s==='string'?s:JSON.stringify(s),{status:st,headers:{...CORS,'Content-Type':'application/json'}});
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const str=(v,n)=>typeof v==='string'&&v.length>0&&v.length<=n;
const idList=(a,n)=>Array.isArray(a)&&a.length>0&&a.length<=n&&a.every(x=>typeof x==='string'&&ID_RE.test(x));
const hex=u=>[...new Uint8Array(u)].map(x=>x.toString(16).padStart(2,'0')).join('');
const sha=async t=>crypto.subtle.digest('SHA-256',new TextEncoder().encode(t));
const fpOf=async(e,s)=>'id_'+hex((await sha('spirit-pet-space/pet-id/v2\n'+e+'\n'+s)).slice(0,16)); // 与客户端 fingerprintOf() 一致
const canon=v=>Array.isArray(v)?'['+v.map(canon).join(',')+']':(v&&typeof v==='object')?'{'+Object.keys(v).filter(k=>v[k]!==undefined).sort().map(k=>JSON.stringify(k)+':'+canon(v[k])).join(',')+'}':JSON.stringify(v); // 与客户端 canon 一致
async function senderOf(L){ // 验信件签名，返回寄信人指纹；签名不对返回 null
  try{const f=L.sender;if(!f||!str(f.encPub,100)||!str(f.signPub,100)||!str(L.sig,200))return null;
    const r={...L};delete r.sig;const k=await crypto.subtle.importKey('raw',b64(f.signPub),{name:'Ed25519'},false,['verify']);
    return await crypto.subtle.verify({name:'Ed25519'},k,b64(L.sig),new TextEncoder().encode('spirit-pet-space/sig/v2\n'+canon(r)))?await fpOf(f.encPub,f.signPub):null}catch{return null}}
async function auth(op,a,extra){ // 验请求签名：两个公钥算出指纹 = 信箱编号；签名覆盖 操作+指纹+时间戳+参数
  try{if(!a||!str(a.encPub,100)||!str(a.signPub,100)||!str(a.sig,200)||!Number.isFinite(a.ts)||Math.abs(Date.now()-a.ts)>SKEW)return null;
    const fp=await fpOf(a.encPub,a.signPub),k=await crypto.subtle.importKey('raw',b64(a.signPub),{name:'Ed25519'},false,['verify']);
    return await crypto.subtle.verify({name:'Ed25519'},k,b64(a.sig),new TextEncoder().encode(`spirit-pet-space/relay/v1\n${op}\n${fp}\n${a.ts}\n${extra}`))?fp:null}catch{return null}}
const count=async env=>(await env.BOX.list({prefix:'a:',limit:num(env.MAX_SEATS,MAX_SEATS)})).keys.length; // 已占座位数
const ttlOf=(env,n)=>{const s=num(env.MAX_SEATS,MAX_SEATS),t=n>=s*TIGHT_RATIO,lo=t?TIGHT_MIN_H:SEAT_MIN_H,hi=t?TIGHT_MAX_H:SEAT_MAX_H;return Math.floor((lo+Math.random()*(hi-lo))*3600)}; // 座位够用：24~48 小时随机；吃紧：6~12 小时随机。到期时间不可预测
const seatOf=async(env,fp)=>{const a=await env.BOX.get('a:'+fp,'json');return a&&a.exp>Date.now()?a:null}; // 座位：{l:允许名单, exp:到期时间, ch:近 24h 扩大名单的时间}
export default{
  async fetch(req,env){ // 任何异常都要带 CORS 头返回，否则浏览器只会显示“CORS 错误”，看不到真正原因
    try{
      const ao=(env.ALLOW_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean),og=req.headers.get('Origin');
      if(ao.length&&og&&og!=='null'&&!ao.includes(og))return reply({error:'origin'},403); // 只挡第三方网页；本地文件（null）和非浏览器客户端不受限，不能当作授权
      if(new URL(req.url).pathname==='/v1/check')return reply({ok:1,kv:!!(env.BOX&&env.BOX.put),v:1}); // 连通性检测：不碰 KV，只报告绑定是否存在
      if(req.method!=='OPTIONS'&&!(env.BOX&&env.BOX.put))return reply({error:'KV 绑定缺失：请在 Worker 设置里添加名为 BOX 的 KV 命名空间绑定'},500);
      return await handle(req,env);
    }catch(e){return reply({error:'server error: '+(e&&e.message||e)},500)}
  }
};
const handle=async(req,env)=>{
  if(req.method==='OPTIONS')return new Response(null,{status:204,headers:CORS});
  if(req.method!=='POST')return reply({error:'method'},405);
  let b;try{const t=await req.text();if(t.length>MAX_BODY)return reply({error:'too large'},413);b=JSON.parse(t)}catch{return reply({error:'bad json'},400)}
  const path=new URL(req.url).pathname;
  if(path==='/v1/drop'){ // 投信：{letter, to:[指纹...]}
    const L=b&&b.letter;
    if(!L||typeof L.id!=='string'||!ID_RE.test(L.id)||!idList(b.to,MAX_TO))return reply({error:'bad drop'},400);
    const v=JSON.stringify(L);if(v.length>MAX_LETTER)return reply({error:'too large'},413);
    const sfp=await senderOf(L);if(!sfp)return reply({error:'bad signature'},400);
    const accepted=[],rejected=[],full=[],now=Date.now();
    await Promise.all([...new Set(b.to)].map(async fp=>{
      const[a,i]=await Promise.all([seatOf(env,fp),env.BOX.get('i:'+fp,'json')]);
      if(!a||!a.l.includes(sfp)){rejected.push(fp);return} // 没开通信箱 / 座位已过期 / 寄信人不在名单里
      if(i&&i.n>=MAX_BOX_N){full.push(fp);return} // 信箱配额已满
      await env.BOX.put(`m:${fp}:${L.id}`,v,{expirationTtl:TTL});
      await env.BOX.put('i:'+fp,JSON.stringify({n:(i?i.n:0)+1,t:now}),{expirationTtl:TTL}); // 信箱索引：信件数 + 版本（etag）
      accepted.push(fp)}));
    return reply({ok:1,accepted,rejected,full,ttl:TTL});
  }
  if(path==='/v1/box/allow'){ // 占座/更新名单：{auth, list:[指纹...], renew}
    const l=b&&b.list;if(!Array.isArray(l)||l.length>MAX_ALLOW||!l.every(x=>typeof x==='string'&&ID_RE.test(x)))return reply({error:'bad list'},400);
    const rn=b.renew===true,fp=await auth('allow',b.auth,(rn?1:0)+':'+l.join(',')); // renew 与名单一起签名
    if(!fp)return reply({error:'auth'},401);
    const now=Date.now(),list=[...new Set(l)],live=await seatOf(env,fp);
    const adds=live?list.filter(x=>!live.l.includes(x)).length:list.length; // 只限制“扩大”名单；收紧（删人）永远允许
    const need=!live||(rn&&live.exp-now<RENEW_LEFT_H*36e5); // 要重新定到期时间：新占座，或续期且剩余不足；别的设备刚续过（剩余充足）则不重复写
    if(live&&adds===0&&live.l.length===list.length&&!need)return reply({ok:1,n:list.length,exp:live.exp}); // 没变化也无需续期：不写 KV，只把当前到期时间告诉客户端
    const ch=(live?live.ch:[]).filter(t=>now-t<864e5);
    let used=null;
    if(!live){ // 新占座：座位总数有上限；同一网络 12 小时内最多开通 N 个不同的信箱（同一信箱重新占座不重复计数）
      const seats=num(env.MAX_SEATS,MAX_SEATS),perIp=num(env.MAX_SEATS_PER_IP,MAX_SEATS_PER_IP);
      const ls=await env.BOX.list({prefix:'a:',limit:seats});used=ls.keys.length;if(used>=seats)return reply({error:'seat full'},503);
      const ik='p:'+hex((await sha('ip\n'+(req.headers.get('CF-Connecting-IP')||''))).slice(0,8)),raw=await env.BOX.get(ik,'json');
      const arr=(Array.isArray(raw)?raw:[]).filter(x=>x&&now-x.t<SEAT_MAX_H*36e5),me=arr.find(x=>x.f===fp);
      if(!me&&arr.length>=perIp)return reply({error:'too many seats from this network'},429);
      if(me)me.t=now;else arr.push({f:fp,t:now});
      await env.BOX.put(ik,JSON.stringify(arr),{expirationTtl:SEAT_MAX_H*3600});
    }
    if(adds>0){if(ch.length>=MAX_ADD_CHANGES)return reply({error:'too many changes'},429);ch.push(now)} // 名单更改过于频繁拒绝
    let exp,ttl;
    if(need){ttl=ttlOf(env,used==null?await count(env):used);exp=now+ttl*1000} // 新占座或续期：重新随机
    else{exp=live.exp;ttl=Math.max(1,Math.floor((exp-now)/1000))} // 只是改名单：到期时间不变，不顺带续期
    await env.BOX.put('a:'+fp,JSON.stringify({l:list,exp,ch}),{expirationTtl:ttl+60});
    return reply({ok:1,n:list.length,exp});
  }
  if(path==='/v1/box/fetch'){ // 取信：{auth, since}；信箱版本没变就不列表（只有 2 次读取）
    const since=Number(b&&b.since)||0,fp=await auth('fetch',b&&b.auth,String(since)); // since 一并签名if(!fp)return reply({error:'auth'},401);
    const i=await env.BOX.get('i:'+fp,'json');
    if(!i||(since&&i.t===since))return reply({letters:[],reads:[],more:false,etag:i?i.t:0,seat:0}); // 没有变化：只读 1 次 KV，不返回座位
    const a=await seatOf(env,fp),seat=a?a.exp:0,settled=Date.now()-i.t>SETTLE_MS; // 距最后一次变更超过 KV 传播窗口，这次 list 才可信；否则不发 etag，客户端下次必重新 list
    const ls=await env.BOX.list({prefix:`m:${fp}:`,limit:MAX_FETCH});
    const out=[];let n=0,more=!ls.list_complete;
    const rs=await env.BOX.list({prefix:`rc:${fp}:`,limit:MAX_RD}),reads=rs.keys.map(k=>{const p=k.name.split(':');return{id:p[3],by:p[2]}});if(!rs.list_complete)more=true; // 回执键：rc:寄信人:读者:信件id
    for(const k of ls.keys){const v=await env.BOX.get(k.name);if(!v)continue;if(out.length&&n+v.length>MAX_RESP){more=true;break}n+=v.length;out.push(v)}
    let et=settled?i.t:0;if(settled&&ls.list_complete&&ls.keys.length!==i.n){await env.BOX.put('i:'+fp,JSON.stringify({n:ls.keys.length,t:Date.now()}),{expirationTtl:TTL});et=0} // 校正计数（信件过期会让计数偏大）；写新版本号，绝不回写读到的旧 t，否则会盖掉并发投递的更新
    return reply(`{"letters":[${out.join(',')}],"reads":${JSON.stringify(reads)},"more":${more},"etag":${et},"seat":${seat}}`);
  }
  if(path==='/v1/read'){ // 已读回执：{auth, to:寄信人指纹, ids:[信件 id...]}
    if(typeof b.to!=='string'||!ID_RE.test(b.to)||!idList(b.ids,MAX_FETCH))return reply({error:'bad read'},400);
    const fp=await auth('read',b.auth,b.to+':'+b.ids.join(','));if(!fp)return reply({error:'auth'},401);
    const a=await seatOf(env,b.to);if(!a||!a.l.includes(fp))return reply({ok:1,done:false}); // 寄信人没开通信箱 / 读者不在名单里
    const i=await env.BOX.get('i:'+b.to,'json');
    await Promise.all(b.ids.map(id=>env.BOX.put(`rc:${b.to}:${fp}:${id}`,'1',{expirationTtl:TTL})));
    await env.BOX.put('i:'+b.to,JSON.stringify({n:i?i.n:0,t:Date.now()}),{expirationTtl:TTL}); // 版本更新，寄信人下次取信才会列表
    return reply({ok:1,done:true});
  }
  if(path==='/v1/box/rdack'){ // 确认已收回执：{auth, rd:[{id,by}]}
    const r=b&&b.rd;if(!Array.isArray(r)||!r.length||r.length>MAX_RD||!r.every(x=>x&&typeof x.id==='string'&&ID_RE.test(x.id)&&typeof x.by==='string'&&ID_RE.test(x.by)))return reply({error:'bad ack'},400);
    const fp=await auth('rdack',b.auth,r.map(x=>x.by+':'+x.id).join(','));if(!fp)return reply({error:'auth'},401);
    await Promise.all(r.map(x=>env.BOX.delete(`rc:${fp}:${x.by}:${x.id}`)));
    return reply({ok:1});
  }
  if(path==='/v1/box/ack'){ // 确认已收：{auth, ids}
    if(!idList(b&&b.ids,MAX_FETCH*2))return reply({error:'bad ack'},400);
    const fp=await auth('ack',b.auth,b.ids.join(','));if(!fp)return reply({error:'auth'},401);
    await Promise.all(b.ids.map(i=>env.BOX.delete(`m:${fp}:${i}`)));
    const i=await env.BOX.get('i:'+fp,'json');if(i)await env.BOX.put('i:'+fp,JSON.stringify({n:Math.max(0,i.n-b.ids.length),t:Date.now()}),{expirationTtl:TTL});
    return reply({ok:1});
  }
  return reply({error:'not found'},404);
};
