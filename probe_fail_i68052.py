#!/usr/bin/env python3
# I68052 read-only: failure text + full event sequence for our two executions
import subprocess, struct, json, time, re, os

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'; CRT = '/pki/client.crt'; KEY = '/pki/client.key'
T = '/temporal.api.workflowservice.v1.WorkflowService/'
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]


def varint(n):
    o = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        if n: o.append(b | 0x80)
        else: o.append(b); return bytes(o)


def fv(f, n): return varint(f << 3) + varint(n)
def fb(f, b): return varint((f << 3) | 2) + varint(len(b)) + b
def fs(f, s): return fb(f, s.encode() if isinstance(s, str) else s)
def fmsg(f, m): return fb(f, m)


def rd_varint(b, i):
    r = 0; s = 0
    while i < len(b):
        x = b[i]; r |= (x & 0x7f) << s; i += 1
        if not x & 0x80: return r, i
        s += 7
    raise ValueError('varint')


def parse(b):
    i = 0; out = []
    while i < len(b):
        k, i = rd_varint(b, i); f = k >> 3; w = k & 7
        if f == 0: raise ValueError('f0')
        if w == 0:
            v, i = rd_varint(b, i); out.append((f, 0, v))
        elif w == 2:
            l, i = rd_varint(b, i)
            if i + l > len(b): raise ValueError('len')
            out.append((f, 2, b[i:i + l])); i += l
        elif w == 5: out.append((f, 5, b[i:i + 4])); i += 4
        elif w == 1: out.append((f, 1, b[i:i + 8])); i += 8
        else: raise ValueError('wt')
    return out


def call(path, body=b'', timeout=25):
    CTR[0] += 1
    fu = '/tmp/f%d' % CTR[0]; hu = '/tmp/fh%d' % CTR[0]; bu = '/tmp/fb%d' % CTR[0]
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    subprocess.run(['curl', '-sS', '--http2', '--connect-timeout', '6', '-m', str(timeout), '-D', hu, '-o', bu,
                    '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
                    '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu],
                   capture_output=True, text=True)
    hdr = open(hu, 'rb').read().decode('utf-8', 'replace') if os.path.exists(hu) else ''
    st = re.findall(r'grpc-status:\s*(\d+)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    for f in (fu, hu, bu):
        try: os.unlink(f)
        except Exception: pass
    return (st[-1] if st else '-'), data


def payload(b):
    if len(b) >= 5 and b[0] == 0:
        return b[5:5 + struct.unpack('>I', b[1:5])[0]]
    return b


def g1(b, f):
    try:
        for ff, w, v in parse(b):
            if ff == f and w == 2: return v
    except Exception: return None


def texts(b, lim=300):
    return ' '.join(x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{4,}', b))[:lim]


def history(ns, wid, rid):
    tok = b''; evs = []
    for pg in range(3):
        req = fs(1, ns) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 40) + (fmsg(4, tok) if tok else b'')
        st, data = call(T + 'GetWorkflowExecutionHistory', req, timeout=30)
        print('GH|pg%d|st=%s|len=%d' % (pg, st, len(data)), flush=True)
        if st != '0': return evs
        pl = payload(data); h = g1(pl, 1) or b''
        for ev in [v for f, w, v in parse(h) if f == 1 and w == 2]:
            evs.append(ev)
        tok = g1(pl, 3) or b''
        if not tok: break
    return evs


wids = [
    ('Q2-OWN', 'builds', 'i68052-q2-own-20261020T144128Z', '01a159c2-a9c9-76ef-bcab-b1a13dcc3064'),
    ('Q1-PLAT', 'builds', 'i68052-q1-plat-20261020T144128Z', '01a159c3-78b7-7eda-8c0c-37c157118b6f'),
]
for tag, ns, wid, rid in wids:
    print('=== %s %s ===' % (tag, wid), flush=True)
    evs = history(ns, wid, rid)
    seq = []
    for ev in evs:
        eid = [v for f, w, v in parse(ev) if f == 1 and w == 0]
        et = [v for f, w, v in parse(ev) if f == 3 and w == 0]
        eid = eid[0] if eid else 0; et = et[0] if et else 0
        seq.append((eid, et))
        if et == 1:  # WorkflowExecutionStarted -> attrs field 6
            sa = g1(ev, 6)
            if sa:
                wt = texts(g1(sa, 1) or b'', 40)
                tq = texts(g1(sa, 5) or b'', 40)
                inp = g1(sa, 6)
                print('START|type=%s|tq=%s|input_len=%d' % (wt, tq, len(inp or b'')), flush=True)
        if et == 3:  # WorkflowExecutionFailed -> attrs field 8
            fa = g1(ev, 8)
            if fa:
                print('WEFAILED|%s' % texts(g1(fa, 1) or b'', 900), flush=True)
        if et == 9:  # WorkflowTaskFailed -> attrs field 14
            fa = g1(ev, 14)
            if fa:
                print('WTFAILED|%s' % texts(g1(fa, 1) or b'', 500), flush=True)
        if et == 7:  # WorkflowTaskCompleted
            print('WFT_COMPLETED|eid=%d' % eid, flush=True)
        if et == 5:
            print('WFT_SCHEDULED|eid=%d' % eid, flush=True)
        if et == 6:
            print('WFT_STARTED|eid=%d|task=%s' % (eid, texts(ev, 60)), flush=True)
    print('SEQ|%s' % ','.join('%d:%d' % x for x in seq), flush=True)
    print('NTEXT|%s' % texts(b''.join(evs), 400), flush=True)

print('===DONE===', flush=True)
