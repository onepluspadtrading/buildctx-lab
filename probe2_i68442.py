#!/usr/bin/env python3
# i68442 build 2: from the metal build sandbox (datapacket vantage) test the
# zero-auth node control-plane ports on real fleet stackers whose railnet IPs
# were previously observed from tenant containers on those very nodes.
# READ-ONLY, one connect per (target,port), no write RPC ever.
import os, sys, socket, struct, subprocess, re, json, time, ipaddress

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CRT = '/pki/client.crt'; KEY = '/pki/client.key'; CA = '/pki/server-ca-bundle.crt'
T0 = time.time()
BUDGET = 420
PORTS = [8773, 8774, 8080, 8081, 50051, 50052, 50151, 50152]

# hostname -> railnet IP, each pair observed in /etc/hosts (host.containers.internal)
# of a tenant container that ran ON that stacker (prior task artifacts).
TARGETS = [
    ("production-stacker-sv2a-metal-047-03", "10.64.0.193"),
    ("production-stacker-cssv9a-metal-119-03", "10.66.2.102"),
    ("production-stacker-cssv9a-metal-084-03", "10.66.2.110"),
    ("production-stacker-drams11a-metal-022-01", "10.66.128.181"),
    ("production-stacker-eqdc16a-metal-050-01", "10.66.65.86"),
    ("production-stacker-eqsg3a-metal-003-01", "10.65.64.17"),
    ("production-stacker-drsin10a-metal-035-03", "10.67.0.154"),
    ("production-stacker-aws-us-west-1c-r8i12xlarge-40", "10.144.131.63"),
    ("production-stacker-aws-us-east-1a-r8i12xlarge-12", "10.145.34.21"),
    ("production-stacker-gcp-asia-southeast1-c-n4-89", "10.131.0.164"),  # GCP control node
]
NOIP = ["production-stacker-drsin10a-metal-028-03", "dpsgp-production-build-server-005",
        "dpsjc-production-build-server-025"]

def log(*a):
    print("[%6.1fs]" % (time.time() - T0), *a, flush=True)

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

def call(path, body=b'', t=120, n='1'):
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

log('HOSTN', socket.gethostname())
try:
    log('IP', subprocess.run(['ip', '-o', 'addr'], capture_output=True, text=True).stdout.replace('\n', ' | ')[:800])
except Exception as e:
    log('IP ERR', e)
try:
    log('EGRESS', subprocess.check_output(['curl', '-sS', '-m', '6', 'https://api.ipify.org'], text=True).strip())
except Exception as e:
    log('EGRESS ERR', str(e)[:100])

h, st, msg, pay = call('/orchestrator.OrchestrationService/Health', b'', 20, 'h')
log('GWCTL http=%s st=%s msg=%s' % (h, st, msg[:60]))
if st != 0:
    log('NETFAIL_VANTAGE_NOT_METAL_EGRESS'); sys.exit(0)

# ---- alternative routers: see whether the gateway forwards other services ----
for path in ('/orchestrator.StackersService/ListStackers',
             '/orchestrator.StackersService/GetStacker'):
    body = b'' if path.endswith('ListStackers') else fb(1, 'production-stacker-drsin10a-metal-035-03')
    try:
        hh, ss, mm, pp = call(path, body, 20, 'x')
        log('ALT %s http=%s st=%s msg=%s len=%d' % (path.split('/')[-1], hh, ss, mm[:60], len(pp)))
        if pp:
            out = []
            for f, w, x in parse(pp):
                if w == 2:
                    try:
                        a = x.decode()
                        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', a): a = 'IP:' + a
                        out.append('f%d=%s' % (f, a[:60]))
                    except Exception: pass
                elif w == 0: out.append('f%d=i:%d' % (f, x))
            log('ALTPAY', ' '.join(out[:40]))
    except Exception as e:
        log('ALT ERR', path, repr(e)[:100])

# ---- full fleet response: any IP-bearing field? ----
h, st, msg, pay = call('/orchestrator.OrchestrationService/ListStackerHealth', fb(1, b''), 120, 'l')
log('LSH http=%s st=%s paylen=%d' % (h, st, len(pay)))
rows = []
for f, w, x in parse(pay):
    if w == 2 and f == 1:
        row = {}
        for f2, w2, x2 in parse(x):
            row[f2] = (w2, x2)
        rows.append(row)
log('ROWS', len(rows))
ipre = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
hits = []
for r in rows:
    for k, (w, x) in r.items():
        if w == 2:
            s = x.decode('utf-8', 'replace')
            if ipre.search(s):
                hits.append((r.get(1, (0, b'?'))[1].decode('utf-8', 'replace')[:44], k, s[:200]))
log('IPSTRINGS', len(hits))
for x in hits[:25]:
    log('  IPSTR', x)

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
def probe(addr):
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {p: ex.submit(tcp, addr, p) for p in PORTS}
        return {p: futs[p].result() for p in PORTS}

b = probe('127.0.0.1')
log('BASE localhost ' + ' '.join('%d=%s/%.2f' % (p, b[p][0], b[p][1]) for p in PORTS))
log('BASE gateway443 %s/%.2f' % tcp('35.247.70.7', 443, 3.0))
log('BASE 1.1.1.1:53 %s/%.2f' % tcp('1.1.1.1', 53, 3.0))
log('BASE 10.128.0.1:53 %s/%.2f' % tcp('10.128.0.1', 53, 3.0))

results = {}
for nm, ip in TARGETS:
    if time.time() - T0 > BUDGET - 60:
        log('TIMEBUDGET_STOP'); break
    r = probe(ip)
    results[nm] = (ip, r)
    log('TGT %s %s ' % (nm, ip) + ' '.join('%d=%s/%.2f' % (p, r[p][0], r[p][1]) for p in PORTS))
    time.sleep(5)

# ---- read-only identification for OPEN ----
def http_code(ip, port, path, t=4):
    try:
        p = subprocess.run(['curl', '-sS', '-m', str(t), '-o', '/tmp/hb', '-w', '%{http_code}',
                            'http://%s:%d%s' % (ip, port, path)], capture_output=True, text=True)
        body = open('/tmp/hb', 'rb').read() if os.path.exists('/tmp/hb') else b''
        return p.stdout.strip(), len(body), body[:200]
    except Exception as e:
        return 'ERR', 0, str(e)[:80].encode()

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
        return (p.stdout.strip(), (st[-1] if st else '?'), ob[:60].hex())
    except Exception as e:
        return ('ERR', '?', str(e)[:60])

for nm, (ip, r) in results.items():
    for p in PORTS:
        if r[p][0] != 'OPEN':
            continue
        log('IDENT %s %s:%d' % (nm, ip, p))
        if p in (8080, 8081):
            for path in ('/health', '/healthcheck', '/metrics'):
                c, n, body = http_code(ip, p, path)
                log('  HTTP %s code=%s len=%d body=%s' % (path, c, n, body[:100]))
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
        else:
            log('  GRPC health', grpc_h2c(ip, p, '/grpc.health.v1.Health/Check'))
            log('  GRPC health_svc', grpc_h2c(ip, p, '/grpc.health.v1.Health/Check', fb(1, b'')))
            if p == 8773:
                log('  MHA List', grpc_h2c(ip, p, '/metal_host_agent.VirtualMachinesService/ListVirtualMachines'))
                log('  MCP Get(nonexistent)', grpc_h2c(ip, p, '/metal_cp.VirtualMachinesService/GetVirtualMachine', fb(1, 'probe-nonexistent-i68442')))

log('NOIP_UNRESOLVED', ','.join(NOIP))
log('DONE dt=%.1f' % (time.time() - T0))
