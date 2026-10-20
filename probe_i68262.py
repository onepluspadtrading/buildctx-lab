#!/usr/bin/env python3
# I68262: decide whether an injected execution on builds/orchestrator is really consumed by the
# platform worker, with correct poller decoding and a long event-sequence window.
# Read-only except: ONE self-project execution + (only if consumed) ONE platform-Station-project
# execution, both with a NON-EXISTENT deploymentID so no snapshot/build can ever be produced;
# any execution still open is Terminated; child-workflow start => immediate Terminate.
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
PLAT_P = 'e766c469-fd0c-4a8c-99c9-d673de872294'
PLAT_E = '048a8d8c-b808-443d-ae9c-91b2f1595d85'
PLAT_S = '01abc7dd-5ef8-4537-a8ea-fd9c8c1c7116'
FAKE_D = 'bb524ff5-b8a0-4b63-afb8-e977bcb219b3'   # known non-existent deployment id
COMMIT = '877c3594d9c3852536a4c2184df111bb850b1af4'
ET = {1: 'WfStarted', 2: 'WfCompleted', 3: 'WfFailed', 4: 'WfTimedOut', 5: 'WfTaskScheduled',
      6: 'WfTaskStarted', 7: 'WfTaskCompleted', 8: 'WfTaskTimedOut', 9: 'WfTaskFailed',
      10: 'ActScheduled', 11: 'ActStarted', 12: 'ActCompleted', 13: 'ActFailed', 14: 'ActTimedOut',
      15: 'TimerStarted', 16: 'TimerFired', 20: 'CancelRequested', 21: 'Canceled', 24: 'Terminated',
      25: 'ChildInitiated', 26: 'ChildStarted', 27: 'ChildCompleted', 28: 'ChildFailed', 29: 'ChildCanceled',
      30: 'ChildTimedOut'}


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
    fu = '/tmp/i68262_%d.req' % CTR[0]; hu = '/tmp/i68262_%d.hdr' % CTR[0]; bu = '/tmp/i68262_%d.bin' % CTR[0]
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    r = subprocess.run(['curl', '-sS', '--http2', '--connect-timeout', '8', '-m', str(timeout), '-D', hu, '-o', bu,
                        '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
                        '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu],
                       capture_output=True, text=True)
    hdr = ''
    if os.path.exists(hu):
        hdr = open(hu, 'rb').read().decode('utf-8', 'replace')
    st = re.findall(r'grpc-status:\s*(\d+)', hdr)
    msg = re.findall(r'grpc-message:\s*([^\r\n]*)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    for f in (fu, hu, bu):
        try: os.unlink(f)
        except Exception: pass
    return {'st': st[-1] if st else '-', 'msg': msg[-1].strip()[:300] if msg else '',
            'n': len(data), 'data': data, 'err': (r.stderr or '')[:120], 'dt': 0}


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


# ---------------- 0. read-only: real input payload metadata + types ----------------
def list_execs(n, q=''):
    body = fs(1, NS) + fv(2, n) + (fs(4, q) if q else b'')
    r = call(T + 'ListWorkflowExecutions', body, 25)
    res = []
    if r['st'] != '0':
        out('LS|st=%s|m=%s|err=%s' % (r['st'], r['msg'], r['err']))
        return res
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
        if r['st'] != '0':
            return None
        pl = payload(r['data']); h = g1(pl, 1) or b''
        evs.extend(all_of(h, 1))
        tok = g1(pl, 3) or b''
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


def dump_real_start_metadata():
    ex = list_execs(25)
    types = sorted(set(x['type'] for x in ex))
    out('LS|n=%d|types=%s' % (len(ex), ','.join(types)))
    for x in ex:
        if x['type'] == 'ScheduleSnapshotAndBuild':
            evs = hist(x['wid'], x['rid'], 1, 40) or []
            for ev in evs:
                if ev_type(ev) == 1:
                    sa = g1(ev, 6) or b''
                    tq = texts(g1(sa, 5) or b'', 60)
                    inp = g1(sa, 6) or b''           # Payloads
                    first = all_of(inp, 1)
                    if not first:
                        out('REALMETA|%s|tq=%s|no_payload' % (x['wid'][:40], tq)); return
                    p0 = first[0]
                    md = g1(p0, 1) or b''
                    entries = []
                    for m in all_of(md, 1):
                        k = (g1(m, 1) or b'').decode('utf-8', 'replace')
                        v = (g1(m, 2) or b'').decode('utf-8', 'replace')
                        entries.append('%s=%s' % (k, v))
                    out('REALMETA|wid=%s|type=%s|tq=%s|payloads=%d|meta=%s|data_len=%d'
                        % (x['wid'][:44], texts(g1(sa, 1) or b'', 40), tq, len(first),
                           ','.join(entries), len(g1(p0, 2) or b'')))
                    return
    out('REALMETA|none_found')


def desc_tq(name, types=(1,), enhanced=True):
    body = fs(1, NS) + fmsg(2, fs(1, name))
    if enhanced:
        body += fv(5, 1)
        for t in types: body += fv(7, t)
        body += fv(8, 1) + fv(9, 1) + fv(10, 1)
    else:
        body += fv(3, types[0]) + fv(4, 1)
    r = call(T + 'DescribeTaskQueue', body, 25)
    out('DTQ|%s|types=%s|enh=%d|st=%s|len=%d|m=%s|err=%s'
        % (name, ','.join(map(str, types)), enhanced, r['st'], r['n'], r['msg'], r['err']))
    if r['st'] != '0':
        return
    pl = payload(r['data'])
    try:
        fields = parse(pl)
    except Exception as ex:
        out('  E|parse %r' % ex); return
    seen = {}
    for f, w, v in fields:
        seen[f] = seen.get(f, 0) + 1
        if f == 1 and w == 2:      # PollerInfo
            ident = ''; secs = 0; rate = None
            for ff, ww, vv in parse(v):
                if ff == 1 and ww == 2: ident = vv.decode('utf-8', 'replace')
                elif ff == 2 and ww == 2:
                    ss = [x for x2, w2, x in parse(vv) if x2 == 1 and w2 == 0]
                    secs = ss[0] if ss else 0
                elif ff == 3 and ww == 1: rate = struct.unpack('<d', vv)[0]
            fresh = int(time.time()) - secs if secs else -1
            out('  POLLER|%s|last=%s|age_s=%s|rate=%s' % (ident[:100], secs, fresh, rate))
        elif f == 4 and w == 2:    # TaskQueueVersionInfo
            for m in all_of(v, 1):  # types_info map entry
                k = [x for x2, w2, x in parse(m) if x2 == 1 and w2 == 0]
                k = k[0] if k else -1
                val = g1(m, 2) or b''
                ps = []
                for p in all_of(val, 1):
                    ident = (g1(p, 1) or b'').decode('utf-8', 'replace')
                    secs = 0
                    t = g1(p, 2)
                    if t:
                        secs = [x for x2, w2, x in parse(t) if x2 == 1 and w2 == 0]
                        secs = secs[0] if secs else 0
                    ps.append('%s(age=%s)' % (ident[:70], int(time.time()) - secs if secs else -1))
                stats = g1(val, 2) or b''
                sv = []
                try:
                    for ff, ww, vv in parse(stats):
                        sv.append('%d=%s' % (ff, vv if ww == 0 else (round(struct.unpack('<d', vv)[0], 3) if ww == 1 else 'b')))
                except Exception: pass
                out('  VTYPE|%s|pollers=%d|%s|stats=%s' % (k, len(ps), ';'.join(ps)[:250], ','.join(sv)[:200]))
        elif f == 2 and w == 2:
            flat = ['%d=%d' % (ff, vv) for ff, ww, vv in parse(v) if ww == 0]
            out('  STATUS|%s' % ','.join(flat[:14]))
    out('  FIELDS|%s' % ','.join('%d:%d' % (k, v) for k, v in sorted(seen.items())))


def parts(name):
    body = fs(1, NS) + fmsg(2, fs(1, name))
    r = call(T + 'ListTaskQueuePartitions', body, 25)
    out('LTP|%s|st=%s|m=%s' % (name[:70], r['st'], r['msg']))
    if r['st'] != '0': return
    for p in all_of(payload(r['data']), 1):
        key = (g1(p, 1) or b'').decode('utf-8', 'replace')
        host = (g1(p, 2) or b'').decode('utf-8', 'replace')
        out('  PART|%s|owner=%s' % (key[:80], host[:80]))


# ---------------- delivery + long window ----------------
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


def start(tag, p, e, s, watch=180):
    wid = 'i68262-%s-%s-%s' % (tag.lower(), TS, uuid.uuid4().hex[:6])
    inp = make_input(p, e, s)
    data = json.dumps(inp).encode()
    pl = fmsg(1, fs(1, 'encoding') + fs(2, 'json/plain')) + fmsg(2, data)
    body = fs(1, NS) + fs(2, wid) + fmsg(3, fs(1, 'ScheduleSnapshotAndBuild')) + fmsg(4, fs(1, QUEUE))
    body += fmsg(5, fmsg(1, pl))
    body += fmsg(6, dur(120)) + fmsg(7, dur(120)) + fmsg(8, dur(10))
    body += fs(9, 'i68262-probe') + fs(10, str(uuid.uuid4())) + fv(11, 2)
    r = call(T + 'StartWorkflowExecution', body, 30)
    out('START|%s|st=%s|m=%s|len=%d|err=%s' % (tag, r['st'], r['msg'], r['n'], r['err']))
    rid = ''
    if r['st'] == '0':
        for f, w, v in parse(payload(r['data'])):
            if f == 1 and w == 2:
                rid = v.decode('utf-8', 'replace'); break
    out('RUNID|%s|%s' % (tag, rid))
    if not rid:
        return
    t0 = time.time(); last = None; consumed = False
    while time.time() - t0 < watch:
        evs = hist(wid, rid, 3, 40)
        if evs is None:
            out('EV|%s|t=%.0f|history_error' % (tag, time.time() - t0))
            time.sleep(5); continue
        seq = [(ev_id(x), ev_type(x)) for x in evs]
        sseq = [t for _, t in seq]
        if sseq != last:
            last = sseq
            out('EV|%s|t=%.1f|%s' % (tag, time.time() - t0, ','.join(ET.get(t, 'T%d' % t) for t in sseq)))
            for ev in evs:
                t = ev_type(ev); eid = ev_id(ev)
                if t == 1:
                    sa = g1(ev, 6) or b''
                    out('  STARTATTR|type=%s|tq=%s|inlen=%d' % (texts(g1(sa, 1) or b'', 40),
                                                              texts(g1(sa, 5) or b'', 60), len(g1(sa, 6) or b'')))
                elif t == 6:
                    a = g1(ev, 11) or b''
                    out('  WORKER|eid=%d|identity=%s' % (eid, texts(g1(a, 2) or b'', 120)))
                elif t == 10:
                    a = g1(ev, 10) or b''
                    at = g1(a, 2) or b''
                    out('  ACTSCHED|eid=%d|name=%s|tq=%s|actid=%s'
                        % (eid, texts(g1(at, 1) or b'', 80), texts(g1(g1(a, 3) or b'', 1) or b'', 80),
                           texts(g1(a, 1) or b'', 60)))
                elif t == 3:
                    a = g1(ev, 8) or b''
                    out('  WFFAILED|%s' % texts(g1(a, 1) or b'', 500))
                elif t == 13:
                    a = g1(ev, 20) or b''
                    out('  ACTFAILED|%s' % texts(g1(a, 1) or b'', 400))
                elif t == 9:
                    a = g1(ev, 14) or b''
                    out('  WTFAILED|%s' % texts(a, 400))
                elif t in (2, 4, 21, 24):
                    out('  TERMINAL|eid=%d|type=%s' % (eid, ET.get(t, t)))
            if 6 in sseq and (7 in sseq or 9 in sseq):
                consumed = True
            if 26 in sseq or 28 in sseq:
                out('CHILD_OBSERVED|%s|terminating_immediately' % tag)
                term(wid, rid)
                return
            if any(x in sseq for x in (2, 3, 4, 21, 24)):
                break
            if 10 in sseq and any(x in sseq for x in (12, 13)):
                break
        time.sleep(5)
    if consumed:
        out('CONSUMED|%s|1' % tag)
    else:
        out('CONSUMED|%s|0' % tag)
    evs = hist(wid, rid, 3, 40) or []
    sseq = [ev_type(x) for x in evs]
    if not any(x in sseq for x in (2, 3, 4, 21, 24)):
        term(wid, rid)
    else:
        out('ALREADY_TERMINAL|%s|last=%s' % (tag, ','.join(ET.get(t, 'T%d' % t) for t in sseq)))
    return consumed


def term(wid, rid):
    r = call(T + 'TerminateWorkflowExecution',
             fs(1, NS) + fmsg(2, fs(1, wid) + fs(2, rid)) + fs(3, 'i68262 cleanup') + fs(5, 'i68262') + fs(6, rid), 25)
    out('TERM|%s|st=%s|m=%s' % (wid[:48], r['st'], r['msg']))


out('===I68262 START=== %s host=%s' % (TS, subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip()))

# 0) positive control + real payload metadata
r = call(T + 'GetSystemInfo', b'', 20)
out('SYSINFO|st=%s|m=%s|len=%d' % (r['st'], r['msg'], r['n']))
dump_real_start_metadata()

# 1) poller / partition matrix (read-only)
desc_tq('orchestrator', (1,), True)
desc_tq('orchestrator', (2,), True)
desc_tq('orchestrator', (1,), False)
parts('orchestrator')
for q in ('builder', 'builder-us-east4', 'builder-europe-west4', 'builder-asia-southeast1'):
    desc_tq(q, (1,), True)
    desc_tq(q, (2,), True)
parts('builder-us-east4')

# 2) delivery #1: self project (fake deployment -> cannot build anything)
c1 = start('OWN', OUR_P, OUR_E, OUR_S, 180)

# 3) delivery #2: platform Station project, only if consumption was observed
if c1:
    out('=== DELIVERY2 platform Station (fake deployment) ===')
    c2 = start('PLAT', PLAT_P, PLAT_E, PLAT_S, 120)
    out('PLAT_CONSUMED=%s' % c2)
else:
    out('DELIVERY2_SKIPPED=no_consumption')

# 4) final list to prove our ids/status + cleanup check
ex = list_execs(40)
mine = [x for x in ex if x['wid'].startswith('i68262-')]
out('MINE|%d|%s' % (len(mine), ';'.join('%s:%s' % (x['wid'][:34], x['rid'][:8]) for x in mine)))

out('===I68262 DONE===')
