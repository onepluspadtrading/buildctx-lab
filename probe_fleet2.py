#!/usr/bin/env python3
# i68245 second pass: compact fleet composition (read-only).
import subprocess, struct, os, sys, re, json, collections

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CRT = '/pki/client.crt'; KEY = '/pki/client.key'; CA = '/pki/server-ca-bundle.crt'

def v(n):
    o = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        if n: o.append(b | 0x80)
        else: o.append(b); return bytes(o)

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

def dec(b):
    return b.decode('utf-8', 'replace')

def row(b):
    d = {}; p = []
    for f, w, x in parse(b):
        if w == 2:
            if f == 9: p.append(dec(x))
            else: d[f] = dec(x)
        elif w == 0: d[f] = x
    return d, p

h, st, msg, pay = call('/orchestrator.OrchestrationService/Health', b'', 25, 'h')
print('HEALTH http=%s st=%s len=%d' % (h, st, len(pay)), flush=True)
if st != 0:
    print('HOST_NETFAIL', flush=True); sys.exit(0)

h, st, msg, pay = call('/orchestrator.OrchestrationService/ListStackerHealth', fb(1, b''), 150, 'l')
print('ZQ|ALL|http=%s|st=%s|paylen=%d' % (h, st, len(pay)), flush=True)
rows = []; zones = []
for f, w, x in parse(pay):
    if w == 2 and f == 1: rows.append(row(x))
    elif w == 2 and f == 2:
        d = {}; c = []
        for f2, w2, x2 in parse(x):
            if w2 == 2:
                if f2 == 4: c.append(dec(x2))
                else: d[f2] = dec(x2)
            elif w2 == 0: d[f2] = x2
        zones.append((d, c))
print('TOTAL %d ZONES %d' % (len(rows), len(zones)), flush=True)
for d, c in zones:
    print('ZR|%s|obs=%s|state=%s|count=%s|thr=%s|auto=%s|manual=%s' % (
        d.get(1, ''), d.get(2), d.get(3, ''), d.get(9), d.get(5), d.get(7), d.get(8)), flush=True)

byz = collections.defaultdict(list)
for d, p in rows: byz[d.get(3, '<none>')].append((d, p))
for z in sorted(byz):
    items = byz[z]
    fam = collections.Counter(re.sub(r'-\d+$', '', d.get(2, '') or d.get(1, '')) for d, p in items)
    states = collections.Counter(d.get(5, '') for d, p in items)
    cord = sum(1 for d, p in items if d.get(13, 0))
    idx = [int(m.group(1)) for d, p in items for m in [re.search(r'-(\d+)$', d.get(1, ''))] if m]
    bad = [d.get(1, '') for d, p in items if d.get(5, '') not in ('HEALTHY',) or d.get(13, 0)][:6]
    print('ZONE|%s|n=%d|families=%s|states=%s|cord=%d|idx=%s|ex=%s|bad=%s' % (
        z, len(items), dict(fam.most_common(4)), dict(states), cord,
        ('%d-%d' % (min(idx), max(idx))) if idx else '-',
        ';'.join(d.get(1, '') for d, p in items[:2]), ','.join(bad)), flush=True)

draining = [(d.get(1, ''), d) for d, p in rows if d.get(15)]
print('HAS_DATA %d' % len(draining), flush=True)
for i, (sid, d) in enumerate(draining[:8]):
    try:
        o = json.loads(d.get(15))
        keys = ','.join(sorted(o.keys()))
    except Exception:
        keys = 'unparsable'
    print('DR|%s|state=%s|keys=%s' % (sid, d.get(5), keys[:300]), flush=True)

# GetStackletConfig: real stacker id used as stacklet_id (source says the controller is a hard-coded empty stub)
for sid in [rows[0][0].get(1, ''), rows[len(rows) // 2][0].get(1, '')]:
    h, st, msg, pay = call('/orchestrator.OrchestrationService/GetStackletConfig', fb(1, sid) + fb(2, b'us-east1'), 30, 'g')
    print('GSC|%s|st=%s|http=%s|paylen=%d|hex=%s' % (sid, st, h, len(pay), pay[:32].hex()), flush=True)

# one placement shape check (uuid-ness only, no values)
h, st, msg, pay = call('/orchestrator.OrchestrationService/GetDrainStatus', fb(1, rows[0][0].get(1, '')), 40, 'd')
n = 0
for f, w, x in parse(pay):
    if w == 2 and f in (2, 4, 8, 9, 11) and n < 2:
        d = {}
        for f2, w2, x2 in parse(x):
            if w2 == 2: d[f2] = dec(x2)
        def shape(s):
            if re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', s): return 'uuid'
            if re.fullmatch(r'[0-9a-f]{16,64}', s): return 'hex%d' % len(s)
            return 'len%d' % len(s)
        print('PLS|f=%d|%s' % (f, '|'.join('f%d=%s' % (k, shape(vv)) for k, vv in sorted(d.items()))), flush=True)
        n += 1
print('DONE', flush=True)
