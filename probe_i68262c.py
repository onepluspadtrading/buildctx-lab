#!/usr/bin/env python3
# I68262 v2: (a) read-only: final event sequence of the two prior injected executions
#             (b) correct DescribeTaskQueue decoding matrix (poller identity / lastAccess / versions_info)
#             (c) delivery #1 self project  + (d) delivery #2 platform Station project
#                 both with a NON-EXISTENT deploymentID and CORRECT payload metadata (encoding=json/plain)
#                 so the orchestrator function decodes and runs its own logic; we stop at the first
#                 evidence of function execution (WfTaskStarted+Completed or ActivityScheduled) and Terminate.
import subprocess, struct, json, time, re, os, uuid

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'; CRT = '/pki/client.crt'; KEY = '/pki/client.key'
T = '/temporal.api.workflowservice.v1.WorkflowService/'
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]
NS = 'builds'; QUEUE = 'orchestrator'
OUR_P = '104cdfa2-f46b-45ed-b2b9-ec4db24b1b3f'
OUR_E = '6bd910b8-f1f5-43e5-b497-5bc2a4c55e3d'
OUR_S = os.environ.get('SVC', '185f72a5-3373-41c1-982c-2af89c6e1191')
PLAT_P = 'e766c469-fd0c-4a8c-99c9-d673de872294'
PLAT_E = '048a8d8c-b808-443d-ae9c-91b2f1595d85'
PLAT_S = '01abc7dd-5ef8-4537-a8ea-fd9c8c1c7116'
FAKE_D = 'bb524ff5-b8a0-4b63-afb8-e977bcb219b3'
COMMIT = '877c3594d9c3852536a4c2184df111bb850b1af4'
ET = {1: 'WfStarted', 2: 'WfCompleted', 3: 'WfFailed', 4: 'WfTimedOut', 5: 'WfTaskScheduled',
      6: 'WfTaskStarted', 7: 'WfTaskCompleted', 8: 'WfTaskTimedOut', 9: 'WfTaskFailed',
      10: 'ActScheduled', 11: 'ActStarted', 12: 'ActCompleted', 13: 'ActFailed', 14: 'ActTimedOut',
      15: 'TimerStarted', 16: 'TimerFired', 20: 'CancelRequested', 21: 'Canceled', 24: 'Terminated',
      25: 'ChildInitiated', 26: 'ChildStarted', 27: 'ChildCompleted', 28: 'ChildFailed', 29: 'ChildCanceled',
      30: 'ChildTimedOut', 31: 'SignalExternal'}


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
def dur(s): return fv(1, int(s))


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
        else: raise ValueError('wt%d' % w)
    return out


def call(path, body=b'', timeout=30):
    CTR[0] += 1
    fu = '/tmp/i68262b_%d.req' % CTR[0]; hu = '/tmp/i68262b_%d.hdr' % CTR[0]; bu = '/tmp/i68262b_%d.bin' % CTR[0]
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    r = subprocess.run(['curl', '-sS', '--http2', '--connect-timeout', '8', '-m', str(timeout), '-D', hu, '-o', bu,
                        '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
                        '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu],
                       capture_output=True, text=True)
    hdr = open(hu, 'rb').read().decode('utf-8', 'replace') if os.path.exists(hu) else ''
    st = re.findall(r'grpc-status:\s*(\d+)', hdr)
    msg = re.findall(r'grpc-message:\s*([^\r\n]*)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    for f in (fu, hu, bu):
        try: os.unlink(f)
        except Exception: pass
    return {'st': st[-1] if st else '-', 'msg': msg[-1].strip()[:300] if msg else '',
            'n': len(data), 'data': data, 'err': (r.stderr or '')[:150]}


def payload(b):
    if len(b) >= 5 and b[0] == 0:
        return b[5:5 + struct.unpack('>I', b[1:5])[0]]
    return b


def g1(b, f):
    try:
        for ff, w, v in parse(b):
            if ff == f and w == 2: return v
    except Exception:
        return None


def all_of(b, f):
    try:
        return [v for ff, w, v in parse(b) if ff == f and w == 2]
    except Exception:
        return []


def texts(b, lim=400):
    return ' '.join(x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{4,}', b))[:lim]


def out(s):
    print(s, flush=True)


# ---------- read-only helpers ----------
def list_execs(n=40):
    r = call(T + 'ListWorkflowExecutions', fs(1, NS) + fv(2, n), 25)
    res = []
    if r['st'] != '0':
        out('LS|st=%s|m=%s|err=%s' % (r['st'], r['msg'], r['err'])); return res
    for ei in all_of(payload(r['data']), 1):
        ex = g1(ei, 1) or b''
        res.append({'wid': (g1(ex, 1) or b'').decode('utf-8', 'replace'),
                    'rid': (g1(ex, 2) or b'').decode('utf-8', 'replace'),
                    'type': (g1(g1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')})
    return res


def hist(wid, rid, pages=3, secs=40):
    tok = b''; evs = []
    for _ in range(pages):
        req = fs(1, NS) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, secs) + (fmsg(4, tok) if tok else b'')
        r = call(T + 'GetWorkflowExecutionHistory', req, 30)
        if r['st'] != '0': return None
        pl = payload(r['data']); h = g1(pl, 1) or b''
        evs.extend(all_of(h, 1)); tok = g1(pl, 3) or b''
        if not tok: break
    return evs


def ev_id(ev):
    try:
        for f, w, v in parse(ev):
            if f == 1 and w == 0: return v
    except Exception: pass
    return 0


def ev_type(ev):
    try:
        for f, w, v in parse(ev):
            if f == 3 and w == 0: return v
    except Exception: pass
    return 0


def dump_seq(tag, wid, rid, maxev=60):
    evs = hist(wid, rid, 3, 40)
    if evs is None:
        out('SEQ|%s|history_error' % tag); return []
    seq = [(ev_id(x), ev_type(x)) for x in evs][-maxev:]
    out('SEQ|%s|%s' % (tag, ','.join('%d:%s' % (i, ET.get(t, 'T%d' % t)) for i, t in seq)))
    for ev in evs:
        t = ev_type(ev); eid = ev_id(ev)
        if t == 1:
            sa = g1(ev, 6) or b''
            out('  ATTR_START|type=%s|tq=%s' % (texts(g1(sa, 1) or b'', 40), texts(g1(sa, 5) or b'', 60)))
        elif t == 6:
            out('  WORKER|eid=%d|tasktoken=%s' % (eid, texts(g1(ev, 11) or b'', 150)))
        elif t in (3, 9, 13):
            fld = 8 if t == 3 else (14 if t == 9 else 20)
            a = g1(ev, fld) or b''
            out('  ERRTEXT|eid=%d|type=%s|%s' % (eid, ET.get(t, t), texts(g1(a, 1) or b'', 700)))
        elif t == 10:
            a = g1(ev, 10) or b''
            out('  ACTSCHED|eid=%d|name=%s|queue=%s' % (eid, texts(g1(g1(a, 2) or b'', 1) or b'', 80),
                                                        texts(g1(g1(a, 3) or b'', 1) or b'', 80)))
    return evs


# ---------- DescribeTaskQueue decoding (field-correct) ----------
def show_versions(v, label='VERS'):
    for m in all_of(v, 1):
        key = g1(m, 1) or b''
        k = [x for a, b, x in parse(key) if a == 1 and b == 0] if key else []
        k = k[0] if k else -1
        val = g1(m, 2) or b''
        ps = []
        for p in all_of(val, 1):
            ident = (g1(p, 1) or b'').decode('utf-8', 'replace')
            t = g1(p, 2) or b''
            secs = [x for a, b, x in parse(t) if a == 1 and b == 0]
            secs = secs[0] if secs else 0
            ps.append('%s(age_s=%s)' % (ident[:90], int(time.time()) - secs if secs else -1))
        stats = g1(val, 2) or b''
        sv = []
        try:
            for a, b, x in parse(stats):
                sv.append('%d=%s' % (a, x if b == 0 else (round(struct.unpack('<d', x)[0], 3) if b == 1 else 'b')))
        except Exception: pass
        out('  %s|type=%s|pollers=%d|%s|stats=%s' % (label, k, len(ps), ';'.join(ps)[:340], ','.join(sv)[:160]))


def desc(tag, name, types=(1,), mode=1):
    body = fs(1, NS) + fmsg(2, fs(1, name))
    for t in types: body += fv(3, t)
    body += fv(4, 1) + fv(5, mode) + fv(6, 1) + fv(7, 1)
    r = call(T + 'DescribeTaskQueue', body, 25)
    out('DTQ|%s|%s|types=%s|mode=%d|st=%s|len=%d|m=%s|err=%s'
        % (tag, name, ','.join(map(str, types)), mode, r['st'], r['n'], r['msg'], r['err']))
    if r['st'] != '0': return
    pl = payload(r['data'])
    try: top = parse(pl)
    except Exception as ex:
        out('  E|%r|HEX=%s' % (ex, pl[:60].hex())); return
    out('  TOP|%s' % ','.join('%d:%d' % (f, w) for f, w, v in top))
    for f, w, v in top:
        if w != 2: continue
        if f == 1:
            ident = (g1(v, 1) or b'').decode('utf-8', 'replace')
            t = g1(v, 2) or b''
            secs = [x for a, b, x in parse(t) if a == 1 and b == 0]
            secs = secs[0] if secs else 0
            out('  POLLER|%s|last=%s|age_s=%s' % (ident[:100], secs, int(time.time()) - secs if secs else -1))
        elif f == 3:
            show_versions(v)
        else:
            try: inner = parse(v)
            except Exception: continue
            out('  F%d_KEYS|%s' % (f, ','.join('%d:%d' % (a, b) for a, b, c in inner))[:300])


# ---------- delivery ----------
def make_input(p, e, s):
    ids = {'projectID': p, 'environmentID': e, 'serviceID': s, 'deploymentID': FAKE_D,
           'snapshotID': str(uuid.uuid4())}
    return {'identifiers': ids,
            'targetRegion': 'us-west1',
            'snapshotConfig': {'rootDirectory': 'i68262_ctx', 'environmentPriority': ['production'],
                               'identifiers': dict(ids)},
            'snapshotGithubRepo': {'owner': 'onepluspadtrading', 'repo': 'buildctx-lab', 'ref': COMMIT},
            'limits': {'maxBuildStepTime': '600s', 'maxWorkflowLifetime': '900s'},
            'builderMode': 'BUILDER_MODE_V3'}


def start(tag, p, e, s, watch=110, stop_at_started=False):
    wid = 'i68262b-%s-%s-%s' % (tag.lower(), TS.replace('T', '-').replace('Z', ''), uuid.uuid4().hex[:6])
    data = json.dumps(make_input(p, e, s)).encode()
    pl = fmsg(1, fs(1, 'encoding') + fs(2, 'json/plain')) + fmsg(2, data)   # correct Payload metadata map
    body = fs(1, NS) + fs(2, wid) + fmsg(3, fs(1, 'ScheduleSnapshotAndBuild')) + fmsg(4, fs(1, QUEUE))
    body += fmsg(5, fmsg(1, pl))
    body += fmsg(6, dur(120)) + fmsg(7, dur(120)) + fmsg(8, dur(10))
    body += fs(9, 'i68262-probe') + fs(10, str(uuid.uuid4())) + fv(11, 2)
    r = call(T + 'StartWorkflowExecution', body, 30)
    out('START|%s|st=%s|m=%s|len=%d|err=%s|wid=%s' % (tag, r['st'], r['msg'], r['n'], r['err'], wid))
    rid = ''
    if r['st'] == '0':
        for f, w, v in parse(payload(r['data'])):
            if f == 1 and w == 2:
                rid = v.decode('utf-8', 'replace'); break
    out('RUNID|%s|%s' % (tag, rid))
    if not rid: return False
    t0 = time.time(); last = None; consumed = False; stop = False
    while time.time() - t0 < watch:
        evs = hist(wid, rid, 3, 40)
        if evs is None:
            time.sleep(4); continue
        sseq = [ev_type(x) for x in evs]
        if sseq != last:
            last = list(sseq)
            out('EV|%s|t=%.1f|%s' % (tag, time.time() - t0, ','.join(ET.get(t, 'T%d' % t) for t in sseq)))
            for ev in evs:
                t = ev_type(ev); eid = ev_id(ev)
                if t == 1:
                    sa = g1(ev, 6) or b''
                    out('  ATTR_START|type=%s|tq=%s|inlen=%d' % (texts(g1(sa, 1) or b'', 40),
                                                                texts(g1(sa, 5) or b'', 60), len(g1(sa, 6) or b'')))
                elif t == 6:
                    out('  WORKER|eid=%d|%s' % (eid, texts(g1(ev, 11) or b'', 170)))
                    consumed = True
                elif t == 7:
                    out('  WFT_COMPLETED|eid=%d' % eid); consumed = True
                elif t == 10:
                    a = g1(ev, 10) or b''
                    out('  ACTSCHED|eid=%d|name=%s|queue=%s|actid=%s'
                        % (eid, texts(g1(g1(a, 2) or b'', 1) or b'', 80),
                           texts(g1(g1(a, 3) or b'', 1) or b'', 80), texts(g1(a, 1) or b'', 60)))
                    consumed = True
                elif t == 3:
                    a = g1(ev, 8) or b''
                    out('  WFFAILED|%s' % texts(g1(a, 1) or b'', 700))
                elif t in (9, 13):
                    fld = 14 if t == 9 else 20
                    a = g1(ev, fld) or b''
                    out('  ERRTEXT|%s|%s' % (ET.get(t, t), texts(g1(a, 1) or b'', 600)))
                elif t in (25, 26):
                    out('  CHILD|eid=%d|type=%s' % (eid, ET.get(t, t)))
            if 6 in sseq and 7 in sseq:
                stop = True
            if stop_at_started and 6 in sseq:
                stop = True
            if 26 in sseq or 10 in sseq or 25 in sseq:
                stop = True
            if any(x in sseq for x in (2, 3, 4, 21, 24)):
                stop = True
        if stop: break
        time.sleep(4)
    evs = hist(wid, rid, 3, 40) or []
    sseq = [ev_type(x) for x in evs]
    if not any(x in sseq for x in (2, 3, 4, 21, 24)):
        r = call(T + 'TerminateWorkflowExecution',
                 fs(1, NS) + fmsg(2, fs(1, wid) + fs(2, rid)) + fs(3, 'i68262 cleanup') + fs(5, 'i68262') + fs(6, rid), 25)
        out('TERM|%s|st=%s|m=%s' % (tag, r['st'], r['msg']))
    else:
        out('ALREADY_TERMINAL|%s|%s' % (tag, ','.join(ET.get(t, 'T%d' % t) for t in sseq)))
    out('CONSUMED|%s|%d' % (tag, 1 if consumed else 0))
    return consumed


out('===I68262b START=== %s host=%s svc=%s'
    % (TS, subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(), OUR_S))
r = call(T + 'GetSystemInfo', b'', 20)
r0_st = r['st']
out('SYSINFO|st=%s|m=%s|len=%d' % (r['st'], r['msg'], r['n']))

# (a) read-only: what did the two PREVIOUS injected executions end with
for tag, wid, rid in (('Q2-OWN-prev', 'i68052-q2-own-20261020T144128Z', '01a159c2-a9c9-76ef-bcab-b1a13dcc3064'),
                      ('Q1-PLAT-prev', 'i68052-q1-plat-20261020T144128Z', '01a159c3-78b7-7eda-8c0c-37c157118b6f')):
    dump_seq(tag, wid, rid)

# (b) poller matrix (read-only): legacy stats + enhanced poller detail, both types
desc('wf_legacy', QUEUE, (1,), 1)
time.sleep(3)
desc('act_legacy', QUEUE, (2,), 1)
time.sleep(3)
desc('both_legacy', QUEUE, (1, 2), 1)
time.sleep(3)
desc('wf_enh', QUEUE, (1,), 2)
time.sleep(3)
desc('both_enh', QUEUE, (1, 2), 2)
time.sleep(3)
desc('builder_wf_legacy', 'builder-us-east4', (1,), 1)
r = call(T + 'ListTaskQueuePartitions', fs(1, NS) + fmsg(2, fs(1, QUEUE)), 25)
out('LTP|%s|st=%s|m=%s' % (QUEUE, r['st'], r['msg']))
if r['st'] == '0':
    for p in all_of(payload(r['data']), 1):
        out('  PART|%s|owner=%s' % ((g1(p, 1) or b'').decode('utf-8', 'replace')[:80],
                                    (g1(p, 2) or b'').decode('utf-8', 'replace')[:80]))
if WHO == 'B':
    out('STEP_B_ONLY=1')

WHO = os.environ.get('WHO', 'A')
if r0_st != '0' or r0_st == '-':
    out('NO_EGRESS|sysinfo_st=%s' % r0_st)
    out('===I68262c DONE(no egress)===')
    raise SystemExit(0)

if WHO == 'A':
    c1 = start('OWNC', OUR_P, OUR_E, OUR_S, 100)
    out('OWN_CONSUMED=%s' % c1)
else:
    c2 = start('PLATC', PLAT_P, PLAT_E, PLAT_S, 70, stop_at_started=True)
    out('PLAT_CONSUMED=%s' % c2)

ex = list_execs(40)
mine = [x for x in ex if x['wid'].startswith('i68262')]
out('MINE|%d|%s' % (len(mine), ';'.join('%s:%s' % (x['wid'][:44], x['rid'][:8]) for x in mine)))
out('===I68262c DONE===')
