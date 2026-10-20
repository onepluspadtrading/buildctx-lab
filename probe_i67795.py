#!/usr/bin/env python3
# I67795: read-only Temporal storage/vm control-plane namespaces via external mTLS gateway.
# Strictly read-only: GetSystemInfo/ListNamespaces/DescribeNamespace/ListWorkflowExecutions/
# DescribeTaskQueue/ListTaskQueuePartitions/GetWorkflowExecutionHistory/ListArchivedWorkflowExecutions.
# No Start/Signal/Update/Terminate/Cancel/Reset/Delete.
import subprocess, struct, json, sys, os, time, re

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
MARK = os.environ.get('MARK', 'I67795')
T = '/temporal.api.workflowservice.v1.WorkflowService/'
CTR = [0]
OUT = []


def p(s, flush=True):
    s = str(s)
    OUT.append(s)
    print(s, flush=flush)


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def fv(f, n):
    return varint(f << 3) + varint(n)


def fb(f, b):
    return varint((f << 3) | 2) + varint(len(b)) + b


def fs(f, s):
    return fb(f, s.encode() if isinstance(s, str) else s)


def fmsg(f, m):
    return fb(f, m)


def rd_varint(b, i):
    r = 0
    s = 0
    while i < len(b):
        x = b[i]
        r |= (x & 0x7f) << s
        i += 1
        if not x & 0x80:
            return r, i
        s += 7
        if s > 63:
            break
    raise ValueError('varint')


def parse(b):
    i = 0
    out = []
    while i < len(b):
        k, i = rd_varint(b, i)
        f = k >> 3
        w = k & 7
        if f == 0:
            raise ValueError('f0')
        if w == 0:
            v, i = rd_varint(b, i)
            out.append((f, 0, v))
        elif w == 2:
            l, i = rd_varint(b, i)
            if i + l > len(b):
                raise ValueError('len')
            out.append((f, 2, b[i:i + l]))
            i += l
        elif w == 5:
            out.append((f, 5, b[i:i + 4]))
            i += 4
        elif w == 1:
            out.append((f, 1, b[i:i + 8]))
            i += 8
        else:
            raise ValueError('wt%d' % w)
    return out


def get1(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 2:
                return v
    except Exception:
        return None
    return None


def getv(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 0:
                return v
    except Exception:
        return None
    return None


def all_of(b, field):
    try:
        return [v for f, w, v in parse(b) if f == field and w == 2]
    except Exception:
        return []


def frame_payload(b):
    if len(b) >= 5 and b[0] == 0:
        l = struct.unpack('>I', b[1:5])[0]
        return b[5:5 + l]
    return b


def protots(v):
    """decode google.protobuf.Timestamp"""
    try:
        r = {}
        for f, w, x in parse(v):
            if w == 0:
                r[f] = x
        return r
    except Exception:
        return {}


def grpc_call(path, body=b'', timeout=10, method='POST'):
    CTR[0] += 1
    n = CTR[0]
    fu = '/tmp/r%d.bin' % n
    bu = '/tmp/b%d.bin' % n
    hu = '/tmp/h%d.txt' % n
    framed = b'\x00' + struct.pack('>I', len(body)) + body
    open(fu, 'wb').write(framed)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '4', '-m', str(timeout), '-D', hu, '-o', bu,
            '-w', '%{http_code}', '--cert', CRT, '--key', KEY, '--cacert', CA,
            '-X', method, G + path, '-H', 'te: trailers']
    if method == 'POST':
        args += ['-H', 'content-type: application/grpc', '--data-binary', '@' + fu]
    t0 = time.time()
    pr = subprocess.run(args, capture_output=True, text=True)
    dt = time.time() - t0
    hdr = ''
    try:
        hdr = open(hu, 'rb').read().decode('utf-8', 'replace')
    except Exception:
        pass
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    msgs = re.findall(r'grpc-message:\s*([^\r\n]*)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    return {'http': pr.stdout.strip(), 'st': (sts[-1] if sts else '-'),
            'msg': (msgs[-1].strip()[:100] if msgs else ''), 'n': len(data),
            'data': data, 'dt': round(dt, 2), 'err': (pr.stderr or '').strip()[:120]}


def printable_bytes(b):
    try:
        s = b.decode('utf-8')
    except Exception:
        return ''
    s = ''.join(c if (31 < ord(c) < 127) else ' ' for c in s)
    return s


# ---------- payload / JSON extraction ----------
json_re = re.compile(rb'\{"', re.S)
SENS = re.compile(r'(token|secret|password|passwd|credential|api_?key|private|dsn|connection|string|keyring|authoriz|cert)', re.I)
INTEREST = re.compile(r'(vm|host|hostname|endpoint|url|addr|address|region|cluster|node|pool|zone|image|repo|registry|bucket|path|port|mount|size|volume|rbd|ceph|s3|bucket|id)$', re.I)


def jsons_from(b, cap=25):
    out = []
    i = 0
    while i < len(b) and len(out) < cap:
        m = json_re.search(b, i)
        if not m:
            break
        s = m.start()
        depth = 0
        j = s
        inq = False
        esc = False
        while j < len(b):
            c = b[j:j + 1]
            if inq:
                if esc:
                    esc = False
                elif c == b'\\':
                    esc = True
                elif c == b'"':
                    inq = False
            else:
                if c == b'"':
                    inq = True
                elif c == b'{':
                    depth += 1
                elif c == b'}':
                    depth -= 1
                    if depth == 0:
                        break
            j += 1
        if j < len(b) and 2 < j - s < 300000:
            try:
                out.append(json.loads(b[s:j + 1].decode('utf-8', 'replace')))
            except Exception:
                pass
        i = max(j, s + 2)
    return out


def summarize_json(o, prefix='', keys=None, sens=None, vals=None, depth=0):
    if keys is None:
        keys = []
    if sens is None:
        sens = set()
    if vals is None:
        vals = []
    if depth > 8:
        return
    if isinstance(o, dict):
        for k, v in o.items():
            kp = prefix + str(k)
            keys.append(kp)
            if SENS.search(str(k)):
                sens.add(kp)
            if isinstance(v, (str, int, float, bool)) and INTEREST.search(str(k)):
                s = str(v)
                if len(s) <= 160:
                    vals.append('%s=%s' % (kp, s))
            summarize_json(v, kp + '.', keys, sens, vals, depth + 1)
    elif isinstance(o, list):
        for it in o[:3]:
            summarize_json(it, prefix, keys, sens, vals, depth + 1)


# ---------- Temporal helpers ----------
def list_we(ns, query, size=20, tok=b'', timeout=15):
    body = fs(1, ns) + fv(2, size) + (fb(3, tok) if tok else b'') + (fs(4, query) if query else b'')
    r = grpc_call(T + 'ListWorkflowExecutions', body, timeout=timeout)
    rows = []
    nxt = b''
    if r['st'] == '0' and r['data']:
        pl = frame_payload(r['data'])
        nxt = get1(pl, 2) or b''
        for ei in all_of(pl, 1):
            ex = get1(ei, 1) or b''
            wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
            rid = (get1(ex, 2) or b'').decode('utf-8', 'replace')
            ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
            status = getv(ei, 5)
            tq = (get1(ei, 12) or b'').decode('utf-8', 'replace')
            st_ts = protots(get1(ei, 3) or b'')
            ct_ts = protots(get1(ei, 4) or b'')
            rows.append({'wid': wid, 'rid': rid, 'type': ty, 'status': status, 'tq': tq,
                         'start': st_ts.get(1, 0), 'close': ct_ts.get(1, 0)})
    return r, rows, nxt


def describe_tq(ns, name, timeout=10):
    body = fs(1, ns) + fmsg(2, fs(1, name)) + fv(3, 1) + fv(4, 1) + fv(5, 1)
    r = grpc_call(T + 'DescribeTaskQueue', body, timeout=timeout)
    ids = []
    if r['st'] == '0' and r['data']:
        pl = frame_payload(r['data'])
        txt = printable_bytes(pl)
        ids = sorted(set(re.findall(r'[0-9]{1,8}@[A-Za-z0-9._:-]{3,90}', txt)))
        if not ids:
            ids = sorted(set(re.findall(r'[A-Za-z0-9._:-]{6,90}', txt)))[:8]
    return r, ids, len(r['data'])


def list_tq_part(ns, name, timeout=10):
    body = fs(1, ns) + fmsg(2, fs(1, name))
    r = grpc_call(T + 'ListTaskQueuePartitions', body, timeout=timeout)
    parts = []
    if r['st'] == '0' and r['data']:
        pl = frame_payload(r['data'])
        for pb in all_of(pl, 1):
            parts.append((get1(pb, 1) or b'').decode('utf-8', 'replace'))
    return r, parts


def history(ns, wid, rid, pages=2, size=20, timeout=25):
    tok = b''
    events = 0
    tqs = set()
    keys = []
    sens = set()
    vals = []
    evtypes = {}
    for pg in range(pages):
        body = fs(1, ns) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, size) + (fmsg(4, tok) if tok else b'')
        r = grpc_call(T + 'GetWorkflowExecutionHistory', body, timeout=timeout)
        if r['st'] != '0' or not r['data']:
            return {'ok': False, 'st': r['st'], 'http': r['http'], 'pg': pg}
        pl = frame_payload(r['data'])
        hist = get1(pl, 1) or b''
        tok = get1(pl, 3) or b''
        for ev in all_of(hist, 1):
            events += 1
            et = getv(ev, 3)
            evtypes[et] = evtypes.get(et, 0) + 1
            sa = get1(ev, 6)
            if sa:
                tq = get1(sa, 5)
                if tq:
                    nm = (get1(tq, 1) or b'').decode('utf-8', 'replace')
                    if nm:
                        tqs.add(nm)
        for j in jsons_from(pl):
            summarize_json(j, '', keys, sens, vals)
        if not tok:
            break
    return {'ok': True, 'events': events, 'tqs': tqs, 'keys': keys, 'sens': sens,
            'vals': vals, 'evtypes': evtypes, 'pages': pg + 1}


# ================= START =================
p('===I67795 START %s %s===' % (MARK, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))
p('host=' + subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())

# --- A controls ---
def show_ctl(tag, r):
    s = '%s|http=%s|st=%s|len=%d|t=%s' % (tag, r['http'], r['st'], r['n'], r['dt'])
    if r['st'] == '0' and r['data']:
        pl = frame_payload(r['data'])
        txt = printable_bytes(pl)
        s += '|S=' + re.sub(r'\s+', ' ', txt)[:90]
    if r['msg']:
        s += '|m=' + r['msg'][:60]
    if r['err']:
        s += '|E=' + r['err'][:60]
    p(s)
    return r


show_ctl('CTL_GetSystemInfo', grpc_call(T + 'GetSystemInfo', b''))
show_ctl('CTL_OTLP', grpc_call('/opentelemetry.proto.collector.trace.v1.TraceService/Export', b''))
show_ctl('CTL_GETROOT', grpc_call('/', b'', method='GET'))

names = []
r = grpc_call(T + 'ListNamespaces', fv(1, 30), timeout=15)
if r['st'] == '0' and r['data']:
    pl = frame_payload(r['data'])
    for nresp in all_of(pl, 1):
        ni = get1(nresp, 1) or b''
        nm = get1(ni, 1)
        if nm:
            names.append(nm.decode('utf-8', 'replace'))
p('NS_FOUND=' + ','.join(names))
show_ctl('CTL_GetClusterInfo', grpc_call(T + 'GetClusterInfo', b''))

TARGETS = ['storage-agent', 'vm-runtime', 'blockstore', 'dataplane-stackers', 'dataplane-namespaces']
for ns in TARGETS:
    if ns not in names:
        p('NSDESC|%s|MISSING' % ns)
        continue
    r = grpc_call(T + 'DescribeNamespace', fs(1, ns), timeout=12)
    if r['st'] == '0' and r['data']:
        pl = frame_payload(r['data'])
        ni = get1(pl, 3) or get1(get1(pl, 1) or b'', 1) or pl
        nid = (get1(ni, 1) or b'').decode('utf-8', 'replace')
        retention = get1(ni, 5)
        rdays = ''
        if retention:
            # google.protobuf.Duration: seconds field 1
            sec = getv(retention, 1) or 0
            rdays = round(sec / 86400.0, 2)
        state = getv(ni, 9)
        p('NSDESC|%s|id=%s|retDays=%s|state=%s|len=%d' % (ns, nid[:40], rdays, state, r['n']))
        # custom search attributes presence
        csa = get1(ni, 7)
        if csa:
            p('   CSA|%s|%s' % (ns, printable_bytes(csa)[:200]))
    else:
        p('NSDESC|%s|st=%s|http=%s|m=%s' % (ns, r['st'], r['http'], r['msg']))

# --- B list workflow executions per namespace ---
QUERIES = [
    ('open', ''),
    ('Running', 'ExecutionStatus="Running"'),
    ('Completed', 'ExecutionStatus="Completed"'),
    ('Failed', 'ExecutionStatus="Failed"'),
    ('Terminated', 'ExecutionStatus="Terminated"'),
    ('Canceled', 'ExecutionStatus="Canceled"'),
    ('TimedOut', 'ExecutionStatus="TimedOut"'),
    ('ContinuedAsNew', 'ExecutionStatus="ContinuedAsNew"'),
    ('7d', 'StartTime > "2026-10-13T00:00:00Z"'),
    ('24h', 'StartTime > "2026-10-19T14:00:00Z"'),
    ('close7d', 'CloseTime > "2026-10-13T00:00:00Z"'),
]
hits = {}  # ns -> list of rows
for ns in TARGETS:
    if ns not in names:
        continue
    seen = set()
    for tag, q in QUERIES:
        r, rows, nxt = list_we(ns, q, size=20)
        extra = ''
        if r['st'] != '0':
            extra = '|m=' + r['msg'][:50]
        types = ','.join(sorted(set(x['type'] for x in rows)))[:120]
        p('L|%s|%s|st=%s|n=%d|len=%d|types=%s%s' % (ns, tag, r['st'], len(rows), r['n'], types, extra))
        for x in rows:
            key = x['rid'] or x['wid']
            if key in seen:
                continue
            seen.add(key)
            hits.setdefault(ns, []).append(x)
            p('   X|%s|%s|%s|%s|st=%s|tq=%s|start=%s' % (
                ns, x['type'][:34], x['wid'][:70], x['rid'][:28], x['status'], x['tq'][:40], x['start']))
        if nxt and len(rows) >= 20 and tag in ('open', '7d', '24h'):
            r2, rows2, _ = list_we(ns, q, size=20, tok=nxt)
            for x in rows2:
                key = x['rid'] or x['wid']
                if key in seen:
                    continue
                seen.add(key)
                hits.setdefault(ns, []).append(x)
                p('   X2|%s|%s|%s|%s|st=%s|tq=%s|start=%s' % (
                    ns, x['type'][:34], x['wid'][:70], x['rid'][:28], x['status'], x['tq'][:40], x['start']))
    if ns not in hits:
        # archived executions fallback
        body = fs(1, ns) + fv(2, 20)
        r = grpc_call(T + 'ListArchivedWorkflowExecutions', body, timeout=15)
        n = 0
        if r['st'] == '0' and r['data']:
            n = len(all_of(frame_payload(r['data']), 1))
        p('ARCH|%s|st=%s|n=%d|m=%s' % (ns, r['st'], n, r['msg'][:60]))

# --- C task queues (fallback when no workflows) ---
TQNAMES = ['storage-agent', 'storage_agent', 'storageagent', 'storage', 'rbd', 'ceph', 'volume', 'volumes',
           'blockstore', 'block-store', 'block', 'dataplane', 'dataplane-stackers', 'dataplane-namespaces',
           'stacker', 'stackers', 'vm-runtime', 'vm_runtime', 'vm-runner', 'vm_runner', 'vmrunner', 'vm',
           'create-vm', 'pull-image-layer', 'image', 'orchestrator', 'default', 'node-agent']
for ns in TARGETS:
    if ns not in names:
        continue
    fnd = []
    for tq in TQNAMES:
        r, ids, ln = describe_tq(ns, tq, timeout=8)
        if r['st'] == '0':
            fnd.append((tq, ids, ln))
            p('TQ|%s|%s|st=0|len=%d|pollers=%s' % (ns, tq, ln, ','.join(ids)[:200] or '-'))
        elif r['st'] not in ('5',):  # 5 = not found
            p('TQ|%s|%s|st=%s|m=%s' % (ns, tq, r['st'], r['msg'][:40]))
    # partition API on top hits
    for tq, ids, ln in fnd[:4]:
        r, parts = list_tq_part(ns, tq)
        p('TQP|%s|%s|st=%s|parts=%s' % (ns, tq, r['st'], ','.join(parts)[:200] or '-'))

# --- D histories ---
MAXH = 6
done = 0
for ns in TARGETS:
    for x in hits.get(ns, []):
        if done >= MAXH:
            break
        h = history(ns, x['wid'], x['rid'], pages=2, size=20)
        done += 1
        if not h.get('ok'):
            p('H|%s|%s|%s|FAIL|st=%s|http=%s|pg=%s' % (ns, x['type'][:28], x['wid'][:50], h.get('st'), h.get('http'), h.get('pg')))
            continue
        uk = sorted(set(h['keys']))
        p('H|%s|%s|%s|st=0|pages=%s|events=%s|tq=%s|keys=%d|ev=%s' % (
            ns, x['type'][:28], x['wid'][:52], h['pages'], h['events'],
            ','.join(sorted(h['tqs']))[:120], len(uk), json.dumps(h['evtypes'])[:120]))
        p('   KEYS=' + ','.join(uk)[:1600])
        if h['sens']:
            p('   SENS=' + ','.join(sorted(h['sens']))[:600])
        if h['vals']:
            p('   VALS=' + ' | '.join(h['vals'])[:1400])

p('===I67795 END %s=== total_calls=%d out_lines=%d' % (MARK, CTR[0], len(OUT)))
