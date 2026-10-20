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



# ================= I67987 VMR3 LOGIC =================
import hashlib, socket


def getv(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 0:
                return v
    except Exception:
        return None
    return None


T = '/temporal.api.workflowservice.v1.WorkflowService/'
PHASE = os.environ.get('PHASE', 'list')
MARK = os.environ.get('MARK', 'I67987VMR3')
T0 = time.time()
DEADLINE = float(os.environ.get('DEADLINE', '520'))
ROWSF = '/tmp/vmr_rows.json'
CANDF = '/tmp/vmr_cands.json'


def left():
    return DEADLINE - (time.time() - T0)


def say(*a):
    print(*a, flush=True)


def list_ns(nsname, q='', size=20, tok=b''):
    body = fs(1, nsname) + fv(2, size) + (fb(3, tok) if tok else b'') + (fs(4, q) if q else b'')
    r = grpc_call(T + 'ListWorkflowExecutions', body, timeout=20)
    rows, nxt = [], b''
    if r['st'] == '0' and r['data']:
        pl = frame_payload(r['data'])
        nxt = get1(pl, 2) or b''
        for ei in all_of(pl, 1):
            ex = get1(ei, 1) or b''
            ty = get1(get1(ei, 2) or b'', 1)
            rows.append({'wid': (get1(ex, 1) or b'').decode('utf-8', 'replace'),
                         'rid': (get1(ex, 2) or b'').decode('utf-8', 'replace'),
                         'type': (ty or b'').decode('utf-8', 'replace')})
    return r, rows, nxt


def hist_full(ns, wid, rid, maxbytes=520000, maxpages=60):
    tok = b''
    out = b''
    pages = 0
    err = None
    while pages < maxpages and left() > 30:
        body = fs(1, ns) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20)
        if tok:
            body += fb(4, tok)
        r = grpc_call(T + 'GetWorkflowExecutionHistory', body, timeout=30)
        if r['st'] != '0' or not r['data']:
            err = r
            break
        pl = frame_payload(r['data'])
        out += get1(pl, 1) or b''
        tok = get1(pl, 3) or b''
        pages += 1
        if not tok or len(out) >= maxbytes:
            break
    return out, pages, err


json_re = re.compile(rb'\{"', re.S)


def jsons_from(b, cap=80):
    out = []
    i = 0
    while True:
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
        if j < len(b) and 2 < j - s < 600000:
            try:
                out.append(json.loads(b[s:j + 1].decode('utf-8', 'replace')))
            except Exception:
                pass
        i = max(j, s + 2)
        if len(out) >= cap:
            break
    return out


SECRET = re.compile(r'(?i)(token|secret|password|passwd|credential|api_?key|dsn|keyring|private_?key|access_?key|authorization|session|bearer|jwt|hmac)')


def sha16(s):
    try:
        b = s.encode() if isinstance(s, str) else s
    except Exception:
        b = str(s).encode()
    return hashlib.sha256(b).hexdigest()[:16]


def dump(o, prefix='C.', out=None, depth=0):
    if out is None:
        out = []
    if depth > 12:
        return out
    if isinstance(o, dict):
        for k, v in o.items():
            kp = prefix + str(k)
            if isinstance(v, str):
                if SECRET.search(str(k)):
                    out.append('%s=***len%d' % (kp, len(v)))
                elif ('PRIVATE KEY' in v) or len(v) > 500:
                    out.append('%s=<str len%d sha256:%s>' % (kp, len(v), sha16(v)))
                elif len(v) <= 300:
                    out.append('%s=%s' % (kp, v.replace('\n', '\\n')))
                else:
                    out.append('%s=<str len%d sha256:%s head=%s>' % (kp, len(v), sha16(v), v[:100].replace('\n', '\\n')))
            elif isinstance(v, (int, float, bool)) or v is None:
                out.append('%s=%s' % (kp, v))
            else:
                dump(v, kp + '.', out, depth + 1)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            if isinstance(v, (dict, list)):
                dump(v, '%s[%d].' % (prefix, i), out, depth + 1)
            elif isinstance(v, str):
                if len(v) > 500:
                    out.append('%s[%d]=<str len%d sha256:%s>' % (prefix, i, len(v), sha16(v)))
                else:
                    out.append('%s[%d]=%s' % (prefix, i, v.replace('\n', '\\n')[:300]))
            else:
                out.append('%s[%d]=%s' % (prefix, i, v))
    return out


HOSTPORT = re.compile(r'(?<![\w.-])([A-Za-z0-9][A-Za-z0-9._-]{2,120}):(\d{2,5})(?![\w])')
IPPORT = re.compile(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\d.])')
RRP = re.compile(r'rrp://[^\s"\'\\,;}]+')
NATS = re.compile(r'(?i)nats[-_a-z]*://[^\s"\'\\,;}]+|\bNATS_[A-Z0-9_]{2,40}\b')
CEPH = re.compile(r'(?i)(?:mon|osd|ceph|msgr[12]|v2):?[= ]?[^\s"\'\\,;}]{2,160}')
VMM = re.compile(r'VMM_KIND_[A-Z_]+|vmm[=:][A-Za-z0-9_]+')
COUNT = re.compile(r'vmruntime|vm-runtime')

cands = {}


def collect(b):
    txt = b.decode('utf-8', 'replace')
    for m in HOSTPORT.findall(txt):
        h, p = m
        if not p.isdigit() or not (1 <= int(p) <= 65535):
            continue
        if h.count('.') == 3 and h.replace('.', '').isdigit():
            cands.setdefault('%s:%s' % (h, p), 0)
        elif not h.replace('-', '').replace('.', '').isdigit() and '.' in h:
            cands.setdefault('%s:%s' % (h, p), 0)
    for m in RRP.findall(txt):
        cands.setdefault('rrp', 0)
        cands.setdefault('rrp|' + m[:200], 0)
    return txt


def print_interesting(txt, tag):
    seen = set()
    for pat, nm in [(RRP, 'RRP'), (NATS, 'NATS'), (VMM, 'VMM')]:
        for x in sorted(set(pat.findall(txt))):
            if x in seen:
                continue
            seen.add(x)
            say('  %s|%s|%s' % (tag, nm, str(x)[:220]))
    hp = set()
    for h, p in HOSTPORT.findall(txt):
        if not p.isdigit():
            continue
        if h.replace('.', '').isdigit() and h.count('.') != 3:
            continue
        hp.add('%s:%s' % (h, p))
    if hp:
        say('  %s|HOSTPORT|%s' % (tag, ','.join(sorted(hp))[:1500]))


say('===I67987-VMR3 %s START %s host=%s===' % (PHASE, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip()))

if PHASE == 'list':
    say('--- controls ---')
    show('OTLP_EXPORT', grpc_call('/opentelemetry.proto.collector.trace.v1.TraceService/Export', b'', target='internal_traces', timeout=15))
    show('GETROOT', grpc_call('/', b'', method='GET', timeout=10))
    show('T_GetSystemInfo', grpc_call(T + 'GetSystemInfo', b'', timeout=12))
    r = grpc_call(T + 'ListNamespaces', fv(1, 20), timeout=15)
    names = []
    if r['st'] == '0' and r['data']:
        pl = frame_payload(r['data'])
        for nresp in all_of(pl, 1):
            ni = get1(nresp, 1) or b''
            nm = get1(ni, 1)
            if nm:
                names.append(nm.decode('utf-8', 'replace'))
    say('NS=' + ','.join(names))
    say('--- vm-runtime list ---')
    rows = []
    tok = b''
    for pg in range(10):
        rr, rws, nxt = list_ns('vm-runtime', '', size=20, tok=tok)
        say('LISTPG|%d|st=%s|http=%s|n=%d|tok=%d' % (pg, rr['st'], rr['http'], len(rws), len(nxt)))
        rows += rws
        tok = nxt
        if not tok or not rws:
            break
    uniq = {}
    for e in rows:
        uniq[(e['wid'], e['rid'])] = e
    rows = list(uniq.values())
    say('ROWS_UNIQ=%d' % len(rows))
    from collections import Counter
    say('TYPES=' + json.dumps(Counter(e['type'] for e in rows)))
    for e in rows:
        say('ROW|%s|%s|%s' % (e['type'], e['wid'], e['rid']))
    json.dump(rows, open(ROWSF, 'w'))

elif PHASE in ('create', 'delete'):
    rows = json.load(open(ROWSF))
    want = 'CreateVmWorkflow' if PHASE == 'create' else 'DeleteVmWorkflow'
    sel = [e for e in rows if e['type'] == want]
    say('PHASE=%s n=%d' % (PHASE, len(sel)))
    for idx, e in enumerate(sel):
        if left() < 40:
            say('DEADLINE_HIT at %d/%d' % (idx, len(sel)))
            break
        h, pages, err = hist_full('vm-runtime', e['wid'], e['rid'])
        say('H|%s|%s|bytes=%d|pages=%d|err=%s' % (e['type'], e['wid'], len(h), pages, (err or {}).get('st')))
        if not h:
            continue
        txt = collect(h)
        print_interesting(txt, 'W%d' % idx)
        objs = jsons_from(h, cap=120)
        # select objects that look like the workflow input spec
        picks = []
        for o in objs:
            if not isinstance(o, dict):
                continue
            keys = set(o.keys())
            if want == 'CreateVmWorkflow' and ('containerSpec' in keys or ('vmID' in keys and 'imageRef' in keys)):
                picks.append(o)
            if want == 'DeleteVmWorkflow' and 'vmID' in keys and ('vmm' in keys or 'VmID' in keys or 'containerSpec' in keys):
                picks.append(o)
        say('OBJS=%d PICKS=%d' % (len(objs), len(picks)))
        # fallback: dump the richest object
        if not picks:
            objs2 = sorted([o for o in objs if isinstance(o, dict)], key=lambda x: len(json.dumps(x, default=str)), reverse=True)
            picks = objs2[:1]
        for oi, o in enumerate(picks[:3]):
            lines = dump(o, '%s%d.' % ('C' if want.startswith('Create') else 'D', oi))
            say('DUMP_%s%d[%d]' % ('CREATE' if want.startswith('Create') else 'DELETE', oi, len(lines)))
            for ln in lines:
                say('  ' + ln[:400])
        # targeted structured print
        for oi, o in enumerate(picks[:3]):
            cs = o.get('containerSpec') or {}
            for k in ('privateNetworkConfig', 'grpcProxy', 'mounts', 'volumes', 'image', 'identifiers', 'envVars', 'networkConfig', 'labels', 'annotations', 'vmm'):
                if k in cs:
                    val = cs[k]
                    if k == 'volumes' and isinstance(val, list):
                        for vi, v in enumerate(val):
                            nm = v.get('name')
                            cont = v.get('content') or ''
                            say('VOL|%s|type=%s|path=%s|len=%s|sha16=%s' % (nm, v.get('type'), v.get('path'), len(cont), sha16(cont)))
                    else:
                        say('CS.%s=%s' % (k, json.dumps(val, default=str)[:1500]))
            for k in ('privateNetworkConfig', 'vmm', 'vmID', 'imageRef', 'imageDigestRef', 'mounts', 'compressedSize', 'envVars'):
                if k in o:
                    say('TOP.%s=%s' % (k, json.dumps(o[k], default=str)[:1500]))
    json.dump(sorted(cands.keys()), open(CANDF, 'w'))

elif PHASE == 'others':
    rows = json.load(open(ROWSF))
    sel = [e for e in rows if e['type'].startswith('PullImageLayer') or (e['type'] not in ('CreateVmWorkflow', 'DeleteVmWorkflow'))]
    say('PHASE=others n=%d' % len(sel))
    allc = {}
    for idx, e in enumerate(sel):
        if left() < 60:
            say('DEADLINE_HIT at %d/%d' % (idx, len(sel)))
            break
        h, pages, err = hist_full('vm-runtime', e['wid'], e['rid'], maxbytes=200000, maxpages=20)
        say('O|%s|%s|bytes=%d|pages=%d|err=%s' % (e['type'], e['wid'], len(h), pages, (err or {}).get('st')))
        if not h:
            continue
        txt = collect(h)
        allc['%s|%s' % (e['type'], e['wid'])] = 1
        print_interesting(txt, 'O%d' % idx)
    json.dump(sorted(cands.keys()), open(CANDF, 'w'))

elif PHASE == 'ns':
    say('--- temporal-system ---')
    for q in ['', 'ExecutionStatus="Running"', 'ExecutionStatus="Completed"', 'ExecutionStatus="Failed"', 'ExecutionStatus="TimedOut"', 'ExecutionStatus="Terminated"', 'ExecutionStatus="Canceled"', 'ExecutionStatus="ContinuedAsNew"']:
        rows = []
        tok = b''
        for pg in range(3):
            rr, rws, nxt = list_ns('temporal-system', q, size=20, tok=tok)
            say('TS_LIST|q=%s|pg=%d|st=%s|http=%s|n=%d|tok=%d' % (q[:40], pg, rr['st'], rr['http'], len(rws), len(nxt)))
            rows += rws
            tok = nxt
            if not tok or not rws:
                break
        for e in rows:
            say('TS_ROW|%s|%s' % (e['type'], e['wid']))
    # task queues
    for tq in ['temporal-system', 'temporal', 'temporal-system-task-queue']:
        rr = grpc_call(T + 'DescribeTaskQueue', fs(1, 'temporal-system') + fmsg(2, fs(1, tq)) + fv(3, 1) + fv(4, 1) + fv(5, 1), timeout=12)
        say('TS_TQ|%s|st=%s|len=%d' % (tq, rr['st'], rr['n']))

    say('--- dataplane-namespaces ---')
    r = grpc_call(T + 'GetSearchAttributes', fs(1, 'dataplane-namespaces'), timeout=15)
    say('DP_SA|st=%s|len=%d' % (r['st'], r['n']))
    if r['st'] == '0' and r['data']:
        pl = frame_payload(r['data'])
        # map field 1 entries (map<string, IndexedValueType>)
        for ent in all_of(pl, 1):
            k = (get1(ent, 1) or b'').decode('utf-8', 'replace')
            v = getv(ent, 2)
            if k:
                say('DP_SA_ENT|%s|%s' % (k, v))
    outs = []
    for q in ['RailwayHostName != ""', 'RailwayRegion != ""', 'RailwayNamespace != ""', 'RailwayClusterLabel != ""',
              'RailwayHostName != "" AND RailwayRegion != ""', 'RailwayRegion = "us-west1"', 'RailwayRegion = "us-east4"',
              'RailwayRegion = "europe-west4"', 'RailwayRegion = "asia-southeast1"', '']:
        rows = []
        tok = b''
        for pg in range(3):
            rr, rws, nxt = list_ns('dataplane-namespaces', q, size=20, tok=tok)
            say('DP_LIST|q=%s|pg=%d|st=%s|http=%s|n=%d|tok=%d' % (q[:68], pg, rr['st'], rr['http'], len(rws), len(nxt)))
            rows += rws
            tok = nxt
            if not tok or not rws:
                break
        for e in rows:
            outs.append(e)
            say('DP_ROW|%s|%s' % (e['type'], e['wid']))
    json.dump(outs, open('/tmp/dp_rows.json', 'w'))

elif PHASE == 'reach':
    c = json.load(open(CANDF)) if os.path.exists(CANDF) else []
    known = set(['152.55.180.152:7411', '152.55.182.11:7411', '152.55.182.12:7411', '152.55.182.13:7411',
                 '152.55.181.109:8774', '152.55.180.152:5432', '152.55.181.108:5432',
                 '10.20.130.15:7235', '10.20.25.140:7235', '10.20.78.142:7235',
                 '162.220.232.44:2227', '208.77.244.4:2227'])
    targets = []
    for x in c:
        if x.startswith('rrp|'):
            continue
        if x in known:
            continue
        if x in ('rrp',):
            continue
        targets.append(x)
    # add rrp host extraction
    for x in c:
        if x.startswith('rrp|'):
            m = re.search(r'rrp://([^/]+)/railway/([^/]+)/node/([^/?#]+)', x)
            if m:
                targets.append('rrp://%s/railway/%s/node/%s' % m.groups())
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]
    say('CAND_TOTAL=%d targets=%d' % (len(c), len(targets)))
    socket.setdefaulttimeout(3)
    for t in targets[:60]:
        if t.startswith('rrp://'):
            say('RRP|%s' % t[:220])
            continue
        h, _, p = t.rpartition(':')
        if not h:
            continue
        res = []
        for ai in range(2):
            try:
                ip = socket.gethostbyname(h)
            except Exception as ex:
                ip = 'DNSFAIL:%s' % str(ex)[:40]
            if ip.startswith('DNSFAIL'):
                res.append(ip)
                break
            try:
                s = socket.create_connection((h, int(p)), timeout=3)
                s.close()
                res.append('OPEN')
                break
            except Exception as ex:
                res.append(type(ex).__name__ + ':' + str(ex)[:40])
            if ai == 0:
                time.sleep(5)
        say('TCP|%s|%s' % (t, '|'.join(res)))
        if res and res[-1] == 'OPEN':
            # minimal read-only banner
            try:
                if p in ('443', '8443', '4443'):
                    rr = subprocess.run(['sh', '-c', "echo | timeout 6 openssl s_client -connect %s:%s -servername %s 2>/dev/null | head -5" % (h, p, h)], capture_output=True, text=True)
                    say('  TLS|%s' % re.sub(r'\s+', ' ', rr.stdout)[:300])
                else:
                    rr = subprocess.run(['sh', '-c', "timeout 5 curl -sS -i --max-time 4 http://%s:%s/ 2>&1 | head -8" % (h, p)], capture_output=True, text=True)
                    say('  HTTP|%s' % re.sub(r'\s+', ' ', rr.stdout)[:300])
            except Exception as ex:
                say('  BANNER_ERR|%s' % str(ex)[:80])

say('===I67987-VMR3 %s END left=%.0f===' % (PHASE, left()))
