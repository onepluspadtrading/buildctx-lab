#!/usr/bin/env python3
# I67677 probe2: deep read-only decode of Temporal workflow payloads (key names / env var names only)
import json, re, sys, os
sys.path.insert(0, '/tmp')
import importlib.util
spec = importlib.util.spec_from_file_location('p1', '/probe.py')
# reuse helpers without running the whole probe
src = open('/probe.py').read().split("print('===I67677 PROBE START")[0]
ns = {}
exec(src, ns)
grpc_call = ns['grpc_call']; parse = ns['parse']; fb = ns['fb']; fs = ns['fs']; fv = ns['fv']; fmsg = ns['fmsg']
all_of = ns['all_of']; get1 = ns['get1']; frame_payload = ns['frame_payload']; dump = ns['dump']

T = '/temporal.api.workflowservice.v1.WorkflowService/'
SENS = ('token', 'secret', 'password', 'passwd', 'dsn', 'connectionstring', 'api_key', 'apikey',
        'private_key', 'credential', 'access_key', 'database_url', 'redis_url', 'authorization')
ENVKEYS = ('variables', 'environmentvariables', 'env', 'envvars', 'environment')
json_re = re.compile(rb'\{"', re.S)


def jsons_from(b):
    out = []
    i = 0
    while True:
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
        if j < len(b) and 2 < j - s < 200000:
            try:
                out.append(json.loads(b[s:j + 1].decode('utf-8', 'replace')))
            except Exception:
                pass
        i = max(j, s + 2)
        if len(out) > 40:
            break
    return out


def walk(o, prefix='', keys=None, envs=None, sens=None):
    keys = keys if keys is not None else []
    envs = envs if envs is not None else set()
    sens = sens if sens is not None else set()
    if isinstance(o, dict):
        for k, v in o.items():
            lk = k.lower()
            if lk in ENVKEYS:
                if isinstance(v, dict):
                    for kk in v.keys():
                        envs.add('%s.%s' % (k, kk))
                elif isinstance(v, list):
                    for it in v[:20]:
                        if isinstance(it, dict):
                            nm = it.get('name') or it.get('key')
                            if nm:
                                envs.add('%s.%s' % (k, nm))
            if any(s in lk for s in SENS):
                sens.add(prefix + k)
            keys.append(prefix + k)
            walk(v, prefix + k + '.', keys, envs, sens)
    elif isinstance(o, list):
        for it in o[:5]:
            walk(it, prefix, keys, envs, sens)


def hist_report(tag, ns_, wid, rid, pages=2):
    tok = b''
    keys = []
    envs = set()
    sens = set()
    evtypes = {}
    tqs = set()
    last_cont = ''
    for pg in range(pages):
        req = fs(1, ns_) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20) + (fmsg(4, tok) if tok else b'')
        r = grpc_call(T + 'GetWorkflowExecutionHistory', req, timeout=25)
        if r['st'] != '0':
            print('H|%s|pg%d|st=%s|http=%s' % (tag, pg, r['st'], r['http']), flush=True)
            return
        pl = frame_payload(r['data'])
        hist = get1(pl, 1) or b''
        evs = all_of(hist, 1)
        tok = get1(pl, 3) or b''
        for ev in evs:
            et = [v for f, w, v in parse(ev) if f == 3 and w == 0]
            et = et[0] if et else 0
            evtypes[et] = evtypes.get(et, 0) + 1
            sa = get1(ev, 6)
            if sa:
                tq = get1(sa, 5)
                if tq:
                    n = (get1(tq, 1) or b'').decode('utf-8', 'replace')
                    if n:
                        tqs.add(n)
        for j in jsons_from(pl):
            walk(j, '', keys, envs, sens)
        # continuation token text
        ct = get1(pl, 5)
        if ct:
            last_cont = ct.decode('utf-8', 'replace')[:60]
        if not tok:
            break
    uk = sorted(set(keys))
    print('H|%s|st=0|pages=%d|events=%s|tq=%s|keys=%d' % (tag, pg + 1, json.dumps(evtypes), ','.join(sorted(tqs)), len(uk)), flush=True)
    print('   KEYS=' + ','.join(uk)[:1100], flush=True)
    if envs:
        print('   ENVNAMES=' + ','.join(sorted(envs))[:600], flush=True)
    if sens:
        print('   SENS=' + ','.join(sorted(sens))[:300], flush=True)
    return tqs


print('===I67677-P2 START===', flush=True)
execs = []
for q in ['', 'WorkflowType="SnapshotAndBuild"', 'WorkflowType="ScheduleSnapshotAndBuild"',
          'ExecutionStatus="Running"', 'WorkflowType="OrchestratorDeploy"']:
    req = fs(1, 'builds') + fv(2, 5) + (fs(4, q) if q else b'')
    r = grpc_call(T + 'ListWorkflowExecutions', req, timeout=20)
    print('L|builds|%s|st=%s|len=%d' % (q or '<all>', r['st'], r['n']), flush=True)
    if r['st'] != '0':
        continue
    pl = frame_payload(r['data'])
    for ei in all_of(pl, 1):
        ex = get1(ei, 1) or b''
        wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
        rid = (get1(ex, 2) or b'').decode('utf-8', 'replace')
        ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
        st = [v for f, w, v in parse(ei) if f == 5 and w == 0]
        if wid:
            execs.append((wid, rid, ty, st[0] if st else -1))
seen = set()
uniq = []
for e in execs:
    if e[1] not in seen:
        seen.add(e[1])
        uniq.append(e)
print('EXECS=%d TYPES=%s' % (len(uniq), ','.join(sorted(set(x[2] for x in uniq)))), flush=True)
for x in uniq[:8]:
    print('  X|%s|%s|%s|status=%s' % (x[2], x[0][:60], x[1][:20], x[3]), flush=True)

tq_all = set()
for wid, rid, ty, st in uniq[:6]:
    r = hist_report('%s/%s' % (ty[:22], wid[-12:]), 'builds', wid, rid)
    if r:
        tq_all |= r

print('===TQ===', flush=True)
for tq in sorted(tq_all | {'orchestrator', 'builder'}):
    for rep in (9, 8):
        req = fs(1, 'builds') + fmsg(2, fs(1, tq)) + fv(3, 1) + fv(rep, 1)
        r = grpc_call(T + 'DescribeTaskQueue', req, timeout=15)
        if r['st'] != '0':
            print('TQ|%s|rep%d|st=%s' % (tq, rep, r['st']), flush=True)
            continue
        pl = frame_payload(r['data'])
        txt = pl.decode('utf-8', 'replace')
        ids = re.findall(r'[A-Za-z0-9._:-]{3,80}@[A-Za-z0-9._:-]{2,60}', txt)
        strs = re.findall(r'[A-Za-z0-9._:-]{6,80}', txt)
        print('TQ|%s|rep%d|len=%d|pollers=%d|idents=%s' % (tq, rep, len(pl), len(ids), ','.join(sorted(set(ids))[:12])), flush=True)
        if not ids:
            print('   S=' + ' | '.join(sorted(set(strs))[:14]), flush=True)
        break

print('===OTHER NS===', flush=True)
for ns_ in ['dataplane-stackers', 'dataplane-namespaces', 'vm-runtime', 'storage-agent', 'blockstore']:
    for q in ['', 'ExecutionStatus="Running"']:
        req = fs(1, ns_) + fv(2, 5) + (fs(4, q) if q else b'')
        r = grpc_call(T + 'ListWorkflowExecutions', req, timeout=15)
        pl = frame_payload(r['data']) if r['st'] == '0' else b''
        n = len(all_of(pl, 1)) if pl else 0
        print('NS|%s|%s|st=%s|n=%d|len=%d' % (ns_, q or '<all>', r['st'], n, r['n']), flush=True)
        if n:
            for ei in all_of(pl, 1)[:5]:
                ex = get1(ei, 1) or b''
                wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
                ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
                print('   NX|%s|%s' % (ty[:40], wid[:70]), flush=True)
            break
print('===I67677-P2 END===', flush=True)
