#!/usr/bin/env python3
# I68052 recon: lock active task queues/pollers in builds+vm-runtime, dump full real input schemas
import subprocess, struct, json, sys, os, time, re

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]
T = '/temporal.api.workflowservice.v1.WorkflowService/'
BUDGET = [52000]


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
            out.append((f, 2, b[i:i + l])); i += l
        elif w == 5:
            out.append((f, 5, b[i:i + 4])); i += 4
        elif w == 1:
            out.append((f, 1, b[i:i + 8])); i += 8
        else:
            raise ValueError('wt%d' % w)
    return out


def call(path, body=b'', timeout=25):
    CTR[0] += 1
    fu = '/tmp/w%d.bin' % CTR[0]
    hu = '/tmp/wh%d.txt' % CTR[0]
    bu = '/tmp/wb%d.bin' % CTR[0]
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '6', '-m', str(timeout), '-D', hu, '-o', bu,
            '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
            '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu]
    t0 = time.time()
    p = subprocess.run(args, capture_output=True, text=True)
    dt = round(time.time() - t0, 2)
    hdr = ''
    try:
        hdr = open(hu, 'rb').read().decode('utf-8', 'replace')
    except Exception:
        pass
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    msgs = re.findall(r'grpc-message:\s*([^\r\n]*)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    for f in (fu, hu, bu):
        try:
            os.unlink(f)
        except Exception:
            pass
    return {'st': (sts[-1] if sts else '-'), 'msg': (msgs[-1].strip()[:200] if msgs else ''),
            'n': len(data), 'data': data, 'dt': dt}


def payload(b):
    if len(b) >= 5 and b[0] == 0:
        l = struct.unpack('>I', b[1:5])[0]
        return b[5:5 + l]
    return b


def out(s):
    if BUDGET[0] <= 0:
        return
    s = s[:BUDGET[0]]
    BUDGET[0] -= len(s)
    print(s, flush=True)


def p1(tag, path, body=b'', lim=300):
    r = call(path, body)
    out('R|%s|st=%s|len=%d|t=%s|m=%s' % (tag, r['st'], r['n'], r['dt'], r['msg']))
    if r['n'] > 5:
        pl = payload(r['data'])
        s = ' '.join(x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{3,}', pl))
        if s:
            out('  P|' + s[:lim])
    return r


def get1(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 2:
                return v
    except Exception:
        return None


def all_of(b, field):
    try:
        return [v for f, w, v in parse(b) if f == field and w == 2]
    except Exception:
        return []


json_re = re.compile(rb'\{"', re.S)


def jsons_from(b):
    res = []
    i = 0
    while i < len(b) and len(res) < 12:
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
                res.append(json.loads(b[s:j + 1].decode('utf-8', 'replace')))
            except Exception:
                pass
        i = max(j, s + 2)
    return res


SAFE_KEYS = {'CodeURI', 'codeURI', 'bucketName', 'host', 'username', 'endpoint', 'identity', 'builder', 'TaskQueueName', 'Region', 'TargetRegion',
             'BuilderVmID', 'buildDriver', 'buildkitRef', 'builderMode', 'Hostname', 'CacheKey',
             'ProjectID', 'ServiceID', 'DeploymentID', 'projectID', 'serviceID', 'environmentID',
             'deploymentID', 'snapshotID', 'CurrentRangeIndex', 'FinalRangeIndex', 'VmID', 'dockerfilePath',
             'rootDirectory', 'buildTime', 'LastEventID', 'LastNodeID', 'LastTransactionID'}
SECRET_KEYS = ('password', 'secretkey', 'accesskey', 'token', 'secret', 'database_url', 'dsn')


def redact(o, depth=0):
    if depth > 8:
        return '<deep>'
    if isinstance(o, dict):
        if depth == 0 and any(k.lower() in ('envvars', 'env', 'variables') for k in o):
            pass
        r = {}
        for k, v in o.items():
            lk = k.lower()
            if lk in ('envvars', 'env', 'environmentvariables', 'variables') and isinstance(v, (dict, list)):
                r[k] = '<redacted env count=%d>' % (len(v))
                continue
            if any(s in lk for s in SECRET_KEYS) and k not in ('bucketName',):
                r[k] = '<redacted len=%d>' % len(str(v))
                continue
            if k in SAFE_KEYS or depth >= 1 and k in ('Identifiers', 'identifiers'):
                r[k] = redact(v, depth + 1) if isinstance(v, (dict, list)) else v
            else:
                r[k] = redact(v, depth + 1) if isinstance(v, (dict, list)) else (
                    ('<str len=%d>' % len(v)) if isinstance(v, str) and len(v) > 0 else v)
        return r
    if isinstance(o, list):
        return [redact(x, depth + 1) for x in o[:3]]
    return o


def list_execs(ns, q='', n=25):
    body = fs(1, ns) + fv(2, n) + (fs(4, q) if q else b'')
    r = call(T + 'ListWorkflowExecutions', body, timeout=25)
    res = []
    if r['st'] != '0':
        out('L|%s|%s|st=%s|m=%s' % (ns, q or '<all>', r['st'], r['msg']))
        return res
    pl = payload(r['data'])
    for ei in all_of(pl, 1):
        ex = get1(ei, 1) or b''
        wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
        rid = (get1(ex, 2) or b'').decode('utf-8', 'replace')
        ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
        st = [v for f, w, v in parse(ei) if f == 5 and w == 0]
        res.append({'wid': wid, 'rid': rid, 'type': ty, 'status': st[0] if st else -1})
    out('L|%s|%s|st=0|n=%d|types=%s' % (ns, q or '<all>', len(res),
        ','.join(sorted(set(x['type'] for x in res)))))
    return res


def hist(ns, wid, rid, pages=2, showjson=False, jcap=9000):
    tok = b''
    evtypes = {}
    tq = ''
    jsons = []
    for pg in range(pages):
        req = fs(1, ns) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 30) + (fmsg(4, tok) if tok else b'')
        r = call(T + 'GetWorkflowExecutionHistory', req, timeout=30)
        if r['st'] != '0':
            out('H|%s|%s|pg%d|st=%s|m=%s' % (ns, wid[:28], pg, r['st'], r['msg']))
            return
        pl = payload(r['data'])
        hist_ = get1(pl, 1) or b''
        evs = all_of(hist_, 1)
        tok = get1(pl, 3) or b''
        for ev in evs:
            et = [v for f, w, v in parse(ev) if f == 3 and w == 0]
            et = et[0] if et else 0
            evtypes[et] = evtypes.get(et, 0) + 1
            sa = get1(ev, 6)
            if sa:
                t = get1(sa, 5)
                if t:
                    nm = (get1(t, 1) or b'').decode('utf-8', 'replace')
                    if nm:
                        tq = nm
        for j in jsons_from(pl):
            jsons.append(j)
        if not tok:
            break
    out('H|%s|%s|st=0|events=%s|tq=%s|jsons=%d' % (ns, wid[:28], json.dumps(evtypes), tq, len(jsons)))
    if showjson:
        # pick the biggest dict
        jsons.sort(key=lambda x: len(json.dumps(x)))
        if jsons:
            s = json.dumps(redact(jsons[-1]), ensure_ascii=False)
            out('  J|%s' % s[:jcap])
    return tq


def desc_tq(ns, name):
    body = fs(1, ns) + fmsg(2, fs(1, name)) + fv(3, 1) + fv(4, 1)
    r = call(T + 'DescribeTaskQueue', body, timeout=25)
    out('DTQ|%s|%s|st=%s|len=%d|m=%s' % (ns, name[:60], r['st'], r['n'], r['msg']))
    if r['st'] != '0':
        return
    pl = payload(r['data'])
    try:
        fields = parse(pl)
    except Exception as ex:
        out('  E|parse %r' % ex)
        fields = []
    for f, w, v in fields:
        if f == 1 and w == 2:  # poller
            ident = ''
            secs = 0
            rate = None
            for ff, ww, vv in parse(v):
                if ff == 1 and ww == 2:
                    ident = vv.decode('utf-8', 'replace')
                elif ff == 2 and ww == 2:
                    s = [x for x2, w2, x in parse(vv) if x2 == 1 and w2 == 0]
                    secs = s[0] if s else 0
                elif ff == 3 and ww == 1:
                    rate = struct.unpack('<d', vv)[0]
            out('  POLLER|%s|last=%s|rate=%s' % (ident[:90], secs, rate))
        elif f == 2 and w == 2:  # status
            flat = []
            for ff, ww, vv in parse(v):
                if ww == 0:
                    flat.append('%d=%d' % (ff, vv))
            out('  STATUS|%s' % ','.join(flat[:12]))
        elif f == 3 and w == 2:
            out('  VERINFO_KEYS|%s' % (get1(v, 1) or b'').decode('utf-8', 'replace')[:200])


def parts(ns, name):
    body = fs(1, ns) + fmsg(2, fs(1, name))
    r = call(T + 'ListTaskQueuePartitions', body, timeout=25)
    out('LTP|%s|%s|st=%s|m=%s' % (ns, name[:60], r['st'], r['msg']))
    if r['st'] != '0':
        return
    pl = payload(r['data'])
    for p in all_of(pl, 1):
        key = (get1(p, 1) or b'').decode('utf-8', 'replace')
        host = (get1(p, 2) or b'').decode('utf-8', 'replace')
        out('  PART|%s|owner=%s' % (key[:90], host[:90]))


print('===I68052-RECON START=== ' + TS, flush=True)
out('host=%s' % subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())
p1('CTL|GetSystemInfo', T + 'GetSystemInfo')

for ns in ('builds', 'vm-runtime'):
    ex = list_execs(ns, '', 25)
    bytype = {}
    for e in ex:
        bytype.setdefault(e['type'], []).append(e)
    # choose samples
    picks = []
    for ty in bytype:
        picks.extend(bytype[ty][:2])
    tqs = []
    shown = 0
    for e in picks:
        if shown >= 6:
            break
        showj = shown < 4
        t = hist(ns, e['wid'], e['rid'], pages=2, showjson=showj, jcap=9000)
        if t:
            tqs.append(t)
        shown += 1
    for t in sorted(set(tqs)):
        desc_tq(ns, t)
        parts(ns, t)

out('===I68052-RECON END===', flush=True)
