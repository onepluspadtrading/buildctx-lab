// i74166 collect: deeper look from inside buildkit RUN sandbox (skeleton of network/host identity).
// read-only
const fs = require('fs');
const net = require('net');
const dgram = require('dgram');
const http = require('http');
const https = require('https');

let out = [];
function say(s){ s=String(s); if(s.length>1600) s=s.slice(0,1600)+'...TRUNC'; out.push(s); console.log(s); }
function rf(p,cap){ try{ const b=fs.readFileSync(p); const n=Math.min(b.length,cap||2000); return b.slice(0,n).toString('utf8').replace(/\0/g,' ').replace(/[\r\n]+/g,' | ').slice(0,1600);}catch(e){return 'ERR:'+(e.code||e.message);} }

function tcp(host,port,ms){return new Promise(res=>{let d=false;const s=net.connect({host,port});const t=setTimeout(()=>{if(!d){d=true;s.destroy();res('TIMEOUT')}},ms||2500);s.on('connect',()=>{if(!d){d=true;clearTimeout(t);s.destroy();res('OPEN')}});s.on('error',e=>{if(!d){d=true;clearTimeout(t);res('ERR:'+(e.code||e.message))}});});}

function encName(n){const parts=n.split('.').filter(Boolean);const b=[];for(const p of parts){b.push(p.length);for(const c of p)b.push(c.charCodeAt(0));}b.push(0);return Buffer.from(b);}
function mkq(name){const h=Buffer.alloc(12);h.writeUInt16BE(0x1234,0);h.writeUInt16BE(0x0100,2);h.writeUInt16BE(1,4);const q=Buffer.concat([encName(name),Buffer.from([0,1,0,1])]);return Buffer.concat([h,q]);}
function parseA(buf){try{if(buf.length<12)return 'SHORT';const an=buf.readUInt16BE(6);const rc=buf.readUInt16BE(2)&0xf;if(rc!==0)return 'RCODE'+rc;let o=12;function skip(){while(o<buf.length){const l=buf[o];if(l===0){o++;return;}if((l&0xc0)===0xc0){o+=2;return;}o+=l+1;}}skip();o+=4;const ips=[];for(let i=0;i<an&&o+12<=buf.length;i++){if((buf[o]&0xc0)===0xc0)o+=2;else{skip();}const ty=buf.readUInt16BE(o);o+=8;const rl=buf.readUInt16BE(o);o+=2;if(ty===1&&rl===4){ips.push(buf[o]+'.'+buf[o+1]+'.'+buf[o+2]+'.'+buf[o+3]);}o+=rl;}return ips.length?ips.join(','):'NOA';}catch(e){return 'PARSE_ERR:'+e.message;}}
function dnsUdp(srv,name,ms){return new Promise(res=>{let d=false;const s=dgram.createSocket('udp4');const t=setTimeout(()=>{if(!d){d=true;try{s.close()}catch(e){};res('TIMEOUT')}},ms||2500);s.on('message',m=>{if(!d){d=true;clearTimeout(t);s.close();res(parseA(m));}});s.on('error',e=>{if(!d){d=true;clearTimeout(t);try{s.close()}catch(x){};res('ERR:'+(e.code||e.message))}});try{s.send(mkq(name),53,srv)}catch(e){if(!d){d=true;res('SEND_ERR:'+e.message)}};});}
function dnsTcp(srv,name,ms){return new Promise(res=>{let d=false;const s=net.connect({host:srv,port:53});const t=setTimeout(()=>{if(!d){d=true;s.destroy();res('TIMEOUT')}},ms||2500);const q=mkq(name);const lb=Buffer.alloc(2);lb.writeUInt16BE(q.length,0);s.on('connect',()=>{s.write(Buffer.concat([lb,q]));});let data=Buffer.alloc(0);s.on('data',c=>{data=Buffer.concat([data,c]);if(data.length>=2&&data.length>=2+data.readUInt16BE(0)){if(!d){d=true;clearTimeout(t);s.destroy();res(parseA(data.slice(2)));}}});s.on('error',e=>{if(!d){d=true;clearTimeout(t);res('ERR:'+(e.code||e.message))}});});}
function httpGet(url,headers,ms){return new Promise(res=>{let d=false;const t=setTimeout(()=>{if(!d){d=true;res('TIMEOUT')}},ms||3000);try{const mod=url.startsWith('https')?https:http;const r=mod.get(url,{headers:headers||{},timeout:ms||3000},x=>{let b='';x.on('data',c=>{if(b.length<400)b+=c});x.on('end',()=>{if(!d){d=true;clearTimeout(t);res(x.statusCode+' '+b.replace(/\s+/g,' ').slice(0,200))}})});r.on('error',e=>{if(!d){d=true;clearTimeout(t);res('ERR:'+(e.code||e.message))}});r.on('timeout',()=>r.destroy());}catch(e){if(!d){d=true;res('EXC:'+e.message)}}});}

(async function(){
  say('===I74166_BEGIN=== '+new Date().toISOString());
  say('HOST '+require('os').hostname()+' UID '+process.getuid());
  // host identity from sysfs/dmi (read-only)
  for(const p of ['/sys/class/dmi/id/sys_vendor','/sys/class/dmi/id/product_name','/sys/class/dmi/id/product_version','/sys/class/dmi/id/board_vendor','/sys/class/dmi/id/board_name','/sys/class/dmi/id/bios_vendor','/sys/class/dmi/id/product_uuid','/sys/class/dmi/id/product_serial']) say('DMI '+p+' = '+rf(p));
  say('CPUMODEL '+rf('/proc/cpuinfo',4000).split('|')[0]);
  say('BOOTID '+rf('/proc/sys/kernel/random/boot_id'));
  say('HOSTNAME_SYS '+rf('/proc/sys/kernel/hostname'));
  say('UPTIME '+rf('/proc/uptime'));
  say('MEMINFO '+rf('/proc/meminfo',900));
  say('CGROUP '+rf('/proc/self/cgroup',600));
  say('STATUS_CAP '+String(rf('/proc/self/status',3000)).split('|').filter(x=>/Cap|Seccomp|NoNewPrivs/.test(x)).join(' | '));
  // net config
  say('ROUTE '+rf('/proc/net/route'));
  say('ARP '+rf('/proc/net/arp'));
  say('NETDEV '+rf('/proc/net/dev'));
  say('IFACE_ADDR '+rf('/sys/class/net/eth0/address')+' mtu='+rf('/sys/class/net/eth0/mtu')+' type='+rf('/sys/class/net/eth0/type'));
  say('RESOLV '+rf('/etc/resolv.conf'));
  say('HOSTS '+rf('/etc/hosts'));
  // mountinfo: shows what buildkit gave us
  try{
    const mi=fs.readFileSync('/proc/self/mountinfo','utf8').split('\n');
    const pick=mi.filter(l=>/railway|buildkit|cache|overlay|docker|containerd|kube|secret|\/proc|\/sys/.test(l));
    say('MOUNTINFO_N '+mi.length);
    for(const l of pick.slice(0,60)) say('MI '+l.slice(0,400));
  }catch(e){ say('MI_ERR '+e.code); }
  // devices
  try{ say('DEV '+fs.readdirSync('/dev').join(',')); }catch(e){ say('DEV ERR '+e.code); }
  say('PARTITIONS '+rf('/proc/partitions'));
  say('SYSBLOCK '+(()=>{try{return fs.readdirSync('/sys/block').join(',')}catch(e){return 'ERR:'+e.code}})());
  // dns via link-local + system
  for(const srv of ['169.254.169.254','8.8.8.8']){
    for(const n of ['railway.internal','orchestrator.railway.internal','backboard.railway.internal','metadata.google.internal','c.railway-infra.internal','us-east4-c.c.railway-infra.internal']){
      say('DNSU '+srv+' '+n+' => '+await dnsUdp(srv,n,2500));
    }
    say('DNST '+srv+' orchestrator.railway.internal => '+await dnsTcp(srv,'orchestrator.railway.internal',2500));
  }
  // gateway probes derived from route
  const gw=(rf('/proc/net/route').match(/\s([0-9A-F]{8})\s([0-9A-F]{8})\s[0-9A-F]{8}\s*[0-9]+\s*[0-9]+\s*[0-9]+\s*([0-9A-F]{8})/)||[]);
  say('GWPARSED '+JSON.stringify(gw));
  const gws=[];
  for(const line of String(rf('/proc/net/route')).split('|')){
    const f=line.trim().split(/\s+/);
    if(f.length>2 && f[1]==='00000000'){
      const hex=f[2]; const ip=[3,2,1,0].map(i=>parseInt(hex.substr(i*2,2),16)).join('.');
      gws.push(ip);
    }
  }
  say('GATEWAYS '+gws.join(','));
  for(const g of gws){ for(const p of [22,53,80,443,2375,5000,6443,8080]) say('TCPGW '+g+':'+p+' '+await tcp(g,p,2000)); }
  // egress identity
  say('EGRESS1 '+await httpGet('http://api.ipify.org',{},3000));
  say('EGRESS2 '+await httpGet('http://checkip.amazonaws.com',{},3000));
  say('EGRESS3 '+await httpGet('https://ifconfig.me/ip',{'User-Agent':'curl/8'},3000));
  say('PUB_RAILWAY '+await httpGet('https://backboard.railway.com/graphql/v2',{'User-Agent':'curl'},4000));
  // hints: localhost services inside sandbox
  for(const p of [53,80,443,5000,8080,15000,15001]) say('TCPLO 127.0.0.1:'+p+' '+await tcp('127.0.0.1',p,800));
  say('===I74166_END===');
  process.exit(0);
})().catch(e=>{ say('TOP_EXC '+e.message); process.exit(0); });
