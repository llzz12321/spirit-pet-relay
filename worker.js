// 灵宠空间 中转站 v2：Cloudflare Worker + Durable Object（SQLite 版，单实例 "main"）。不再使用 KV。
// 架构：Worker 只做 CORS、体积检查、签名验证（CPU 重活留在这里）；通过验证的操作交给 Relay（DO）执行。
//  · 全部状态在 DO 的 SQLite 里：强一致、可事务，没有 KV 的“最终一致”窗口，所以去掉了 etag/settle 一套；取信一次查询即可
//  · 无账号，全靠签名：信箱编号 = 灵宠指纹。占座（允许名单）、投信、取信、已读回执、确认删除，规则同 v1
//  · 预算：免费版 DO 每天约 10 万行写入（请核对官方文档）。DAY_BUDGET 默认 5 万，留一半余量；UTC 零点重置
//    每小时池 = 剩余预算 ÷ 当天剩余小时，闲置自然顺延；保底 = 池 ÷ max(近 15 分钟活跃灵宠数, MIN_ACTIVE)
//    灵宠可超出保底“借用”到保底的 BORROW 倍，但本小时全站池用完即止。收费按“整条消息的生命周期”预付给寄信人：
//    投信每个收信人 5 行（信件写入+删除、回执写入+删除、杂项）；确认收信/确认回执不再扣费，被投信的人不会因清理信箱而变忙
//  · 取信不进预算，只按灵宠限频（每分钟 SOFT_PER_MIN 次，DO 内存计数，单实例所以准确）；响应里带建议轮询间隔 poll
//  · 超额返回 429 {error:'busy', retry:秒}，客户端把该灵宠标为“中转·忙”
// 环境变量（可选）：ALLOW_ORIGINS、MAX_SEATS、MAX_SEATS_PER_IP、DAY_BUDGET、SOFT_PER_MIN
import {DurableObject} from 'cloudflare:workers';
const TTL=7*86400, MAX_LETTER=300000, MAX_BODY=400000, MAX_ALLOW=200, MAX_TO=50, MAX_FETCH=20, MAX_RD=40, MAX_RESP=12e6, SKEW=5*60*1000;
const MAX_SEATS=50, SEAT_MIN_H=24, SEAT_MAX_H=48, TIGHT_MIN_H=6, TIGHT_MAX_H=12, TIGHT_RATIO=0.8, RENEW_LEFT_H=4, MAX_BOX_N=30, MAX_RC=200, MAX_ADD_CHANGES=10, MAX_SEATS_PER_IP=10;
const DAY_BUDGET=50000, MIN_ACTIVE=5, BORROW=3, ACTIVE_MS=15*6e4, SOFT_PER_MIN=40, DROP_COST=5;
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
async function auth(op,a,extra){ // 验请求签名：签名覆盖 操作+指纹+时间戳+参数
  try{if(!a||!str(a.encPub,100)||!str(a.signPub,100)||!str(a.sig,200)||!Number.isFinite(a.ts)||Math.abs(Date.now()-a.ts)>SKEW)return null;
    const fp=await fpOf(a.encPub,a.signPub),k=await crypto.subtle.importKey('raw',b64(a.signPub),{name:'Ed25519'},false,['verify']);
    return await crypto.subtle.verify({name:'Ed25519'},k,b64(a.sig),new TextEncoder().encode(`spirit-pet-space/relay/v1\n${op}\n${fp}\n${a.ts}\n${extra}`))?fp:null}catch{return null}}

export class Relay extends DurableObject{
  constructor(ctx,env){super(ctx,env);this.sql=ctx.storage.sql;this.act=new Map();this.hit=new Map();
    ['CREATE TABLE IF NOT EXISTS seat(fp TEXT PRIMARY KEY,l TEXT,exp INTEGER,ch TEXT)', // 座位：允许名单、到期时间、近 24h 扩大名单的时间
     'CREATE TABLE IF NOT EXISTS mail(fp TEXT,id TEXT,v TEXT,t INTEGER,PRIMARY KEY(fp,id))', // 信箱里的信（整封密文）
     'CREATE TABLE IF NOT EXISTS rc(fp TEXT,by TEXT,id TEXT,t INTEGER,PRIMARY KEY(fp,by,id))', // 已读回执：寄信人信箱 fp，读者 by，信件 id
     'CREATE TABLE IF NOT EXISTS ipseat(ip TEXT,fp TEXT,t INTEGER,PRIMARY KEY(ip,fp))', // 同一网络近期开通的信箱
     'CREATE TABLE IF NOT EXISTS q(fp TEXT PRIMARY KEY,h INTEGER,s REAL)', // 灵宠本小时已用额度
     'CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT)'].forEach(s=>this.sql.exec(s));
    ctx.blockConcurrencyWhile(async()=>{if(!await ctx.storage.getAlarm())await ctx.storage.setAlarm(Date.now()+36e5)})}
  async alarm(){ // 每小时清理过期数据
    const now=Date.now(),hr=Math.floor(now/36e5);
    this.sql.exec('DELETE FROM mail WHERE t<?',now-TTL*1000);this.sql.exec('DELETE FROM rc WHERE t<?',now-TTL*1000);
    this.sql.exec('DELETE FROM seat WHERE exp<?',now);this.sql.exec('DELETE FROM ipseat WHERE t<?',now-SEAT_MAX_H*36e5);this.sql.exec('DELETE FROM q WHERE h<?',hr-1);
    await this.ctx.storage.setAlarm(now+36e5)}
  one(q,...a){return this.sql.exec(q,...a).toArray()[0]}
  rows(q,...a){return this.sql.exec(q,...a).toArray()}
  seatOf(fp){const a=this.one('SELECT l,exp,ch FROM seat WHERE fp=?',fp);return a&&a.exp>Date.now()?{l:JSON.parse(a.l),exp:a.exp,ch:JSON.parse(a.ch)}:null}
  seatCount(){return this.one('SELECT COUNT(*) c FROM seat WHERE exp>?',Date.now()).c}
  ttlOf(n){const s=num(this.env.MAX_SEATS,MAX_SEATS),t=n>=s*TIGHT_RATIO,lo=t?TIGHT_MIN_H:SEAT_MIN_H,hi=t?TIGHT_MAX_H:SEAT_MAX_H;return Math.floor((lo+Math.random()*(hi-lo))*3600)} // 座位够用 24~48 小时随机；吃紧 6~12 小时随机
  activeN(){const t=Date.now()-ACTIVE_MS;let n=0;for(const[k,v]of this.act)if(v>t)n++;else this.act.delete(k);return n}
  soft(fp){const now=Date.now(),s=this.hit.get(fp);if(this.hit.size>2000)for(const[k,v]of this.hit)if(now-v.t>6e4)this.hit.delete(k);if(!s||now-s.t>6e4){this.hit.set(fp,{t:now,n:1});return false}return ++s.n>num(this.env.SOFT_PER_MIN,SOFT_PER_MIN)}
  budget(fp){ // 当前额度状态（不扣费）
    const now=Date.now(),day=Math.floor(now/864e5),hr=Math.floor(now/36e5),D=num(this.env.DAY_BUDGET,DAY_BUDGET),r=this.one("SELECT v FROM meta WHERE k='m'"),m=r?JSON.parse(r.v):{};
    const used=m.day===day?m.used:0,same=m.day===day&&m.hr===hr,hs=same?m.hs:0,hp=same?m.hp:Math.max(0,(D-used)/(24-new Date(now).getUTCHours())); // 整点定下本小时池：剩余/剩余小时
    const act=this.activeN(),fl=hp/Math.max(act,MIN_ACTIVE),q=this.one('SELECT h,s FROM q WHERE fp=?',fp),s=q&&q.h===hr?q.s:0;
    return{day,hr,D,used,hs,hp,fl,s,act,room:Math.max(0,Math.max(fl-s,Math.min(fl*BORROW-s,hp-hs))),retry:Math.max(60,Math.ceil(((hr+1)*36e5-now)/1000))}}
  charge(fp,cost){ // 返回 0 = 通过；否则返回建议等待的秒数
    const b=this.budget(fp);if(cost>b.room)return b.retry;
    this.sql.exec('INSERT OR REPLACE INTO q VALUES(?,?,?)',fp,b.hr,b.s+cost);
    this.sql.exec("INSERT OR REPLACE INTO meta VALUES('m',?)",JSON.stringify({day:b.day,hr:b.hr,hp:b.hp,hs:b.hs+cost,used:b.used+cost+2}));return 0} // +2：记账本身的两行写入
  drop(sfp,id,v,to){
    const w=this.charge(sfp,to.length*DROP_COST);if(w)return[429,{error:'busy',retry:w}]; // 按寄信灵宠计；向没开通的信箱乱投也要付费
    const now=Date.now(),accepted=[],rejected=[],full=[];
    for(const fp of to){const a=this.seatOf(fp);
      if(!a||!a.l.includes(sfp)){rejected.push(fp);continue} // 没开通信箱 / 座位已过期 / 寄信人不在名单里
      if(!this.one('SELECT 1 x FROM mail WHERE fp=? AND id=?',fp,id)&&this.one('SELECT COUNT(*) c FROM mail WHERE fp=?',fp).c>=MAX_BOX_N){full.push(fp);continue}
      this.sql.exec('INSERT OR REPLACE INTO mail VALUES(?,?,?,?)',fp,id,v,now);accepted.push(fp)}
    return[200,{ok:1,accepted,rejected,full,ttl:TTL}]}
  allow(fp,list,rn,ip){ // 占座/更新名单；续期与名单一起签名
    const now=Date.now(),live=this.seatOf(fp),adds=live?list.filter(x=>!live.l.includes(x)).length:list.length; // 只限制“扩大”名单；收紧永远允许
    const need=!live||(rn&&live.exp-now<RENEW_LEFT_H*36e5);
    if(live&&adds===0&&live.l.length===list.length&&!need)return[200,{ok:1,n:list.length,exp:live.exp}];
    const w=this.charge(fp,live?1:2);if(w)return[429,{error:'busy',retry:w}];
    const ch=(live?live.ch:[]).filter(t=>now-t<864e5);let used=null;
    if(!live){const seats=num(this.env.MAX_SEATS,MAX_SEATS),perIp=num(this.env.MAX_SEATS_PER_IP,MAX_SEATS_PER_IP);used=this.seatCount();if(used>=seats)return[503,{error:'seat full'}];
      const arr=this.rows('SELECT fp FROM ipseat WHERE ip=? AND t>?',ip,now-SEAT_MAX_H*36e5);
      if(!arr.some(x=>x.fp===fp)&&arr.length>=perIp)return[429,{error:'too many seats from this network'}]; // 同一网络 48 小时内最多 N 个不同的信箱
      this.sql.exec('INSERT OR REPLACE INTO ipseat VALUES(?,?,?)',ip,fp,now)}
    if(adds>0){if(ch.length>=MAX_ADD_CHANGES)return[429,{error:'too many changes'}];ch.push(now)}
    const exp=need?now+this.ttlOf(used==null?this.seatCount():used)*1000:live.exp;
    this.sql.exec('INSERT OR REPLACE INTO seat VALUES(?,?,?,?)',fp,JSON.stringify(list),exp,JSON.stringify(ch));
    return[200,{ok:1,n:list.length,exp}]}
  pull(fp){ // 取信：一次查询；不扣预算，只限频
    const now=Date.now();this.act.set(fp,now);if(this.soft(fp))return[429,{error:'busy',retry:30}];
    const a=this.seatOf(fp),ms=this.rows('SELECT id,v FROM mail WHERE fp=? AND t>? ORDER BY t LIMIT ?',fp,now-TTL*1000,MAX_FETCH+1),rs=this.rows('SELECT by,id FROM rc WHERE fp=? AND t>? LIMIT ?',fp,now-TTL*1000,MAX_RD+1);
    let more=ms.length>MAX_FETCH||rs.length>MAX_RD,n=0;const out=[];
    for(const m of ms.slice(0,MAX_FETCH)){if(out.length&&n+m.v.length>MAX_RESP){more=true;break}n+=m.v.length;out.push(m.v)}
    return[200,`{"letters":[${out.join(',')}],"reads":${JSON.stringify(rs.slice(0,MAX_RD).map(r=>({id:r.id,by:r.by})))},"more":${more},"etag":0,"seat":${a?a.exp:0},"poll":${Math.max(8,Math.ceil(this.activeN()*.6))}}`]}
  read(fp,to,ids){ // 已读回执：读者 fp 须在寄信人 to 的允许名单里
    const a=this.seatOf(to);if(!a||!a.l.includes(fp))return[200,{ok:1,done:false}];
    if(this.one('SELECT COUNT(*) c FROM rc WHERE fp=?',to).c+ids.length>MAX_RC)return[200,{ok:1,done:false}]; // 回执堆积：寄信人不取就不再收
    const w=this.charge(fp,ids.length);if(w)return[429,{error:'busy',retry:w}];
    const now=Date.now();for(const id of ids)this.sql.exec('INSERT OR REPLACE INTO rc VALUES(?,?,?,?)',to,fp,id,now);return[200,{ok:1,done:true}]}
  rdack(fp,rd){for(const x of rd)this.sql.exec('DELETE FROM rc WHERE fp=? AND by=? AND id=?',fp,x.by,x.id);return[200,{ok:1}]}
  ack(fp,ids){for(const i of ids)this.sql.exec('DELETE FROM mail WHERE fp=? AND id=?',fp,i);return[200,{ok:1}]}
  quota(fp){const b=this.budget(fp);return[200,{ok:1,room:Math.floor(b.room),floor:Math.floor(b.fl),cap:Math.floor(b.fl*BORROW),spent:Math.floor(b.s),hp:Math.floor(b.hp),hs:Math.floor(b.hs),used:Math.floor(b.used),budget:b.D,active:b.act,seats:this.seatCount(),maxSeats:num(this.env.MAX_SEATS,MAX_SEATS),resetIn:b.retry}]}
}

export default{
  async fetch(req,env){ // 任何异常都要带 CORS 头返回，否则浏览器只会显示“CORS 错误”
    try{
      const ao=(env.ALLOW_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean),og=req.headers.get('Origin');
      if(ao.length&&og&&og!=='null'&&!ao.includes(og))return reply({error:'origin'},403); // 只挡第三方网页；本地文件（null）和非浏览器客户端不受限，不能当作授权
      if(new URL(req.url).pathname==='/v1/check')return reply({ok:1,do:!!(env.RELAY&&env.RELAY.idFromName),v:2}); // 连通性检测：只报告绑定是否存在
      if(req.method!=='OPTIONS'&&!(env.RELAY&&env.RELAY.idFromName))return reply({error:'Durable Object 绑定缺失：请添加名为 RELAY 的绑定（类 Relay，SQLite 版），见 wrangler.toml'},500);
      return await handle(req,env);
    }catch(e){return reply({error:'server error: '+(e&&e.message||e)},500)}
  }
};
const handle=async(req,env)=>{
  if(req.method==='OPTIONS')return new Response(null,{status:204,headers:CORS});
  if(req.method!=='POST')return reply({error:'method'},405);
  let b;try{const t=await req.text();if(t.length>MAX_BODY)return reply({error:'too large'},413);b=JSON.parse(t)}catch{return reply({error:'bad json'},400)}
  const path=new URL(req.url).pathname,stub=env.RELAY.get(env.RELAY.idFromName('main')),out=r=>reply(r[1],r[0]);
  if(path==='/v1/drop'){ // 投信：{letter, to:[指纹...]}
    const L=b&&b.letter;
    if(!L||typeof L.id!=='string'||!ID_RE.test(L.id)||!idList(b.to,MAX_TO))return reply({error:'bad drop'},400);
    const v=JSON.stringify(L);if(v.length>MAX_LETTER)return reply({error:'too large'},413);
    const sfp=await senderOf(L);if(!sfp)return reply({error:'bad signature'},400);
    return out(await stub.drop(sfp,L.id,v,[...new Set(b.to)]));
  }
  if(path==='/v1/box/allow'){ // 占座/更新名单：{auth, list:[指纹...], renew}
    const l=b&&b.list;if(!Array.isArray(l)||l.length>MAX_ALLOW||!l.every(x=>typeof x==='string'&&ID_RE.test(x)))return reply({error:'bad list'},400);
    const rn=b.renew===true,fp=await auth('allow',b.auth,(rn?1:0)+':'+l.join(','));
    if(!fp)return reply({error:'auth'},401);
    const ip=hex((await sha('ip\n'+(req.headers.get('CF-Connecting-IP')||''))).slice(0,8));
    return out(await stub.allow(fp,[...new Set(l)],rn,ip));
  }
  if(path==='/v1/box/fetch'){ // 取信：{auth, since}（since 仅为兼容旧客户端，已不使用）
    const since=Number(b&&b.since)||0,fp=await auth('fetch',b&&b.auth,String(since));
    if(!fp)return reply({error:'auth'},401);
    return out(await stub.pull(fp));
  }
  if(path==='/v1/read'){ // 已读回执：{auth, to:寄信人指纹, ids:[信件 id...]}
    if(typeof b.to!=='string'||!ID_RE.test(b.to)||!idList(b.ids,MAX_FETCH))return reply({error:'bad read'},400);
    const fp=await auth('read',b.auth,b.to+':'+b.ids.join(','));if(!fp)return reply({error:'auth'},401);
    return out(await stub.read(fp,b.to,b.ids));
  }
  if(path==='/v1/box/rdack'){ // 确认已收回执：{auth, rd:[{id,by}]}
    const r=b&&b.rd;if(!Array.isArray(r)||!r.length||r.length>MAX_RD||!r.every(x=>x&&typeof x.id==='string'&&ID_RE.test(x.id)&&typeof x.by==='string'&&ID_RE.test(x.by)))return reply({error:'bad ack'},400);
    const fp=await auth('rdack',b.auth,r.map(x=>x.by+':'+x.id).join(','));if(!fp)return reply({error:'auth'},401);
    return out(await stub.rdack(fp,r));
  }
  if(path==='/v1/box/ack'){ // 确认已收：{auth, ids}
    if(!idList(b&&b.ids,MAX_FETCH*2))return reply({error:'bad ack'},400);
    const fp=await auth('ack',b.auth,b.ids.join(','));if(!fp)return reply({error:'auth'},401);
    return out(await stub.ack(fp,b.ids));
  }
  if(path==='/v1/box/quota'){ // 查询本灵宠额度：{auth}
    const fp=await auth('quota',b&&b.auth,'');if(!fp)return reply({error:'auth'},401);
    return out(await stub.quota(fp));
  }
  return reply({error:'not found'},404);
};
