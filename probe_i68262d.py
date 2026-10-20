#!/usr/bin/env python3
# I68262d — decisive: (1) read-only replay of the two earlier injected executions' histories
#                    (2) poller matrix with defensive decode
#                    (3) ONE self-project delivery with CORRECT payload metadata
#                    (4) ONE platform-Station-project delivery
# Both use a NON-EXISTENT deploymentID; we terminate at the first WfTaskStarted/Completed/Activity/Child.
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
      25: 'ChildInitiated', 26: 'ChildStarted', 27: 'ChildCompleted', 28: 'ChildFailed',
      29: 'ChildCanceled', 30: 'ChildTimedOut', 31: 'SignalExternal', 32: 'MarkerRecorded'}


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


def sp(b):
    try: return parse(b)
    except Exception: return []


def g1(b, f):
    for ff, w, v in sp(b):
        if ff == f and w == 2: return v
    return None


def all_of(b, f):
    return [v for ff, w, v in sp(b) if ff == f and w == 2]


def texts(b, lim=400):
    return ' '.join(x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{4,}', b or b''))[:lim]


def out(s):
    print(s, flush=True)


def call(path, body=b'', timeout=30):
    CTR[0] += 1
    fu = '/tmp/i68262d_%d.req' % CTR[0]; hu = '/tmp/i68262d_%d.hdr' % CTR[0]; bu = '/tmp/i68262d_%d.bin' % CTR[0]
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
            'n': len(data), 'data': data, 'err': (r.stderr or '')[:130]}


def payload(b):
    if len(b) >= 5 and b[0] == 0:
        return b[5:5 + struct.unpack('>I', b[1:5])[0]]
    return b


def list_execs(n=30):
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


def evnum(ev, f):
    for a, b, x in sp(ev):
        if a == f and b == 0: return x
    return 0


def dump_seq(tag, wid, rid):
    evs = hist(wid, rid, 3, 40)
    if evs is None:
        out('SEQ|%s|history_error' % tag); return
    out('SEQ|%s|n=%d|%s' % (tag, len(evs), ','.join('%d:%s' % (evnum(x, 1), ET.get(evnum(x, 3), 'T%d' % evnum(x, 3))) for x in evs)))
    for ev in evs:
        t = evnum(ev, 3)
        if t == 1:
            sa = g1(ev, 6) or b''
            inp = g1(sa, 6) or b''
            p0 = (all_of(inp, 1) or [b''])[0]
            md = g1(p0, 1) or b''
            ents = []
            for m in all_of(md, 1):
                ents.append('%s=%s' % ((g1(m, 1) or b'').decode('utf-8', 'replace'),
                                       (g1(m, 2) or b'').decode('utf-8', 'replace')))
            out('  START|type=%s|tq=%s|meta_pairs=%d[%s]|p0_head=%s'
                % (texts(g1(sa, 1) or b'', 40), texts(g1(sa, 5) or b'', 50), len(ents), ','.join(ents)[:120],
                   p0[:24].hex()))
        elif t == 6:
            out('  WORKER|eid=%d|%s' % (evnum(ev, 1), texts(g1(ev, 11) or b'', 160)))
        elif t == 3:
            out('  WFFAILED|%s' % texts(g1(g1(ev, 8) or b'', 1) or b'', 600))
        elif t in (9, 13):
            fld = 14 if t == 9 else 20
            out('  ERR|%s|%s' % (ET.get(t), texts(g1(g1(ev, fld) or b'', 1) or b'', 400)))


# ---- DescribeTaskQueue: defensive, legacy(3 assoc type / 4 report) and enhanced(5 mode 2) ----
def dtq(tag, name, assoc=(1,), report=True, mode=None):
    body = fs(1, NS) + fmsg(2, fs(1, name))
    for t in assoc: body += fv(3, t)
    if report: body += fv(4, 1)
    if mode is not None: body += fv(5, mode) + fv(6, 1) + fv(7, 1)
    r = call(T + 'DescribeTaskQueue', body, 25)
    out('DTQ|%s|%s|assoc=%s|mode=%s|st=%s|len=%d|m=%s|err=%s'
        % (tag, name, ','.join(map(str, assoc)), mode, r['st'], r['n'], r['msg'], r['err']))
    if r['st'] != '0': return
    pl = payload(r['data'])
    top = sp(pl)
    out('  TOP|%s|head=%s' % (','.join('%d:%d' % (f, w) for f, w, v in top), pl[:40].hex()))

    def pollers_of(blob, label):
        for p in all_of(blob, 1):
            ident = (g1(p, 1) or b'').decode('utf-8', 'replace')
            secs = evnum(g1(p, 2) or b'', 1)
            out('  POLLER|%s|%s|last=%s|age_s=%s' % (label, ident[:90], secs,
                                                     int(time.time()) - secs if secs else -1))

    for f, w, v in top:
        if w != 2: continue
        if f == 1:
            pollers_of(fb(1, v), 'legacy')
        elif f == 3:                     # versions_info map<int32, TaskQueueVersionInfo>
            for m in all_of(v, 1):
                k = evnum(g1(m, 1) or b'', 1)
                val = g1(m, 2) or b''
                out('  VERS|type=%s|keys=%s' % (k, ','.join('%d:%d' % (a, b) for a, b, c in sp(val))))
                pollers_of(val, 'v%s' % k)
                stats = g1(val, 2) or b''
                sv = []
                for a, b, x in sp(stats):
                    sv.append('%d=%s' % (a, x if b == 0 else (round(struct.unpack('<d', x)[0], 3) if b == 1 else 'b')))
                out('  STATS|type=%s|%s' % (k, ','.join(sv)[:160]))



def post_check(t0, tag):
    """terminate ONLY executions that are provably ours (their StartWorkflow input carries FAKE_D)."""
    time.sleep(3)
    ex = list_execs(40)
    out('POSTCHK|%s|n=%d' % (tag, len(ex)))
    for x in ex:
        if x['wid'].startswith('i68262d-'):
            continue
        evs = hist(x['wid'], x['rid'], 1, 40) or []
        blob = b''.join(evs)
        if FAKE_D.encode() in blob or OUR_P.encode() in blob and x['type'] in ('SnapshotAndBuild', 'ScheduleBuildAndPublishImage', 'ScheduleSnapshotRepo', 'ScheduleSnapshotAndBuild'):
            tstart = [evnum(e, 2) for e in evs if evnum(e, 3) == 1]
            tstart = tstart[0] if tstart else 0
            tsec = (tstart - 116444736000000000) / 1e7 if tstart > 1e17 else 0
            out('  OWNED_CHILD?|%s|type=%s|started_epoch=%.0f|age_s=%.0f' % (x['wid'][:60], x['type'], tsec, time.time() - tsec if tsec else -1))
            if tsec and time.time() - tsec < 300:
                r = call(T + 'TerminateWorkflowExecution',
                         fs(1, NS) + fmsg(2, fs(1, x['wid']) + fs(2, x['rid'])) + fs(3, 'i68262 cleanup child') + fs(5, 'i68262') + fs(6, x['rid']), 25)
                out('  TERM_CHILD|%s|st=%s|m=%s' % (x['wid'][:50], r['st'], r['msg']))
            else:
                out('  SKIP_CHILD_OLD|%s' % x['wid'][:50])

def make_input(p, e, s):
    ids = {'projectID': p, 'environmentID': e, 'serviceID': s, 'deploymentID': FAKE_D,
           'snapshotID': str(uuid.uuid4())}
    return {'identifiers': ids,
            'targetRegion': 'usw',
            'snapshotConfig': {'rootDirectory': 'i68262_ctx', 'environmentPriority': ['production'],
                               'identifiers': dict(ids)},
            'snapshotGithubRepo': {'owner': 'onepluspadtrading', 'repo': 'buildctx-lab', 'ref': COMMIT},
            'limits': {'maxBuildStepTime': '600s', 'maxWorkflowLifetime': '900s'},
            'builderMode': 'BUILDER_MODE_V3'}


def start(tag, p, e, s, watch=90):
    wid = 'i68262d-%s-%s-%s' % (tag.lower(), TS.replace('T', '-').replace('Z', ''), uuid.uuid4().hex[:6])
    data = json.dumps(make_input(p, e, s)).encode()
    pl = fmsg(1, fs(1, 'encoding') + fs(2, 'json/plain')) + fmsg(2, data)
    body = (fs(1, NS) + fs(2, wid) + fmsg(3, fs(1, 'ScheduleSnapshotAndBuild')) + fmsg(4, fs(1, QUEUE))
            + fmsg(5, fmsg(1, pl)) + fmsg(6, dur(120)) + fmsg(7, dur(120)) + fmsg(8, dur(10))
            + fs(9, 'i68262-probe') + fs(10, str(uuid.uuid4())) + fv(11, 2))
    r = call(T + 'StartWorkflowExecution', body, 30)
    out('START|%s|st=%s|m=%s|len=%d|err=%s' % (tag, r['st'], r['msg'], r['n'], r['err']))
    rid = ''
    if r['st'] == '0':
        rid = (g1(payload(r['data']), 1) or b'').decode('utf-8', 'replace')
    out('RUNID|%s|%s|wid=%s' % (tag, rid, wid))
    if not rid: return False
    t0 = time.time(); last = None; seen = []; stop = False
    while time.time() - t0 < watch:
        evs = hist(wid, rid, 3, 40)
        if evs is None:
            time.sleep(3); continue
        sseq = [evnum(x, 3) for x in evs]
        if sseq != last:
            last = list(sseq)
            out('EV|%s|t=%.1f|%s' % (tag, time.time() - t0, ','.join(ET.get(t, 'T%d' % t) for t in sseq)))
            for ev in evs:
                t = evnum(ev, 3); eid = evnum(ev, 1)
                if t == 6:
                    out('  WFT_STARTED|eid=%d|worker=%s' % (eid, texts(g1(ev, 11) or b'', 160)))
                    seen.append('WftStarted'); stop = True
                elif t == 7:
                    out('  WFT_COMPLETED|eid=%d' % eid); seen.append('WftCompleted')
                elif t == 3:
                    out('  WFFAILED|%s' % texts(g1(g1(ev, 8) or b'', 1) or b'', 700)); stop = True
                elif t == 10:
                    a = g1(ev, 10) or b''
                    out('  ACTSCHED|eid=%d|name=%s|queue=%s' % (eid, texts(g1(g1(a, 2) or b'', 1) or b'', 70),
                                                               texts(g1(g1(a, 3) or b'', 1) or b'', 70)))
                    stop = True
                elif t in (25, 26):
                    out('  CHILD|eid=%d|%s' % (eid, ET.get(t))); stop = True
                elif t == 9:
                    out('  WFTFAILED|%s' % texts(g1(g1(ev, 14) or b'', 1) or b'', 500)); stop = True
            if any(x in sseq for x in (2, 3, 4, 21, 24)):
                stop = True
        if stop: break
        time.sleep(2)
    evs = hist(wid, rid, 3, 40) or []
    sseq = [evnum(x, 3) for x in evs]
    terminal = any(x in sseq for x in (2, 3, 4, 21, 24))
    if not terminal:
        r = call(T + 'TerminateWorkflowExecution',
                 fs(1, NS) + fmsg(2, fs(1, wid) + fs(2, rid)) + fs(3, 'i68262 cleanup') + fs(5, 'i68262') + fs(6, rid), 25)
        out('TERM|%s|st=%s|m=%s' % (tag, r['st'], r['msg']))
    evs2 = hist(wid, rid, 3, 40) or []
    out('FINAL|%s|%s' % (tag, ','.join('%d:%s' % (evnum(x, 1), ET.get(evnum(x, 3), evnum(x, 3))) for x in evs2)))
    return 6 in sseq or 7 in sseq


out('===I68262d START=== %s host=%s svc=%s'
    % (TS, subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(), OUR_S))
r0 = call(T + 'GetSystemInfo', b'', 20)
out('SYSINFO|st=%s|m=%s|len=%d' % (r0['st'], r0['msg'], r0['n']))
if r0['st'] != '0':
    out('NO_EGRESS|%s' % r0['err'])
    out('===I68262d DONE(no egress)===')
    raise SystemExit(0)

dump_seq('prev_own', 'i68052-q2-own-20261020T144128Z', '01a159c2-a9c9-76ef-bcab-b1a13dcc3064')
dump_seq('prev_plat', 'i68052-q1-plat-20261020T144128Z', '01a159c3-78b7-7eda-8c0c-37c157118b6f')

dtq('legacy_wf', QUEUE, (1,), True)
time.sleep(3)
dtq('legacy_act', QUEUE, (2,), True)
time.sleep(3)
dtq('enh_wf', QUEUE, (1,), False, 2)
time.sleep(2)
# (mixed queue probe omitted)

out('=== delivery #1: OWN project, fake deploymentID ===')
c1 = start('OWN', OUR_P, OUR_E, OUR_S, 90)
out('OWN_CONSUMED=%s' % c1)
post_check(time.time(), 'after_own')

out('=== delivery #2: platform Station project, fake deploymentID ===')
c2 = start('PLAT', PLAT_P, PLAT_E, PLAT_S, 90)
out('PLAT_CONSUMED=%s' % c2)
post_check(time.time(), 'after_plat')

ex = list_execs(30)
mine = [x for x in ex if x['wid'].startswith('i68262')]
out('MINE|%d|%s' % (len(mine), ';'.join('%s:%s' % (x['wid'][:46], x['rid'][:8]) for x in mine)))
out('===I68262d DONE===')
