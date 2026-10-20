#!/usr/bin/env python3
# I67795 probe2: full structured decode of vm-runtime control-plane workflows + ns configs.
import os, re, json, subprocess, time
BASE = '/base.py'
src = open(BASE).read()
src = src.split('# ================= START =================')[0]
ns = {}
exec(src, ns)
grpc_call = ns['grpc_call']; fs = ns['fs']; fv = ns['fv']; fmsg = ns['fmsg']
all_of = ns['all_of']; get1 = ns['get1']; getv = ns['getv']; frame_payload = ns['frame_payload']
parse = ns['parse']; printable_bytes = ns['printable_bytes']; jsons_from = ns['jsons_from']
T = '/temporal.api.workflowservice.v1.WorkflowService/'
p = ns['p']
MARK = os.environ.get('MARK', 'I67795P2')

MASK = re.compile(r'(?i)(token|secret|password|passwd|credential|api_?key|dsn|keyring|private_?key|access_?key|authorization|session)')
IDRE = re.compile(r'[0-9]{1,7}@[A-Za-z0-9._-]{3,120}')
HOSTRE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{4,90}(?:-production-[A-Za-z0-9._-]+|production-build-server[A-Za-z0-9._-]*)')
INTRE = re.compile(r'\b(?:vmr|builder|vm-runtime|temporal|storage|blockstore|dataplane)-[A-Za-z0-9._-]{2,80}')


def dump(o, prefix='', out=None, depth=0):
    if out is None:
        out = []
    if depth > 9:
        return out
    if isinstance(o, dict):
        for k, v in o.items():
            kp = prefix + str(k)
            if isinstance(v, str):
                if MASK.search(str(k)):
                    out.append('%s=***len%d' % (kp, len(v)))
                elif len(v) <= 220:
                    out.append('%s=%s' % (kp, v))
                else:
                    out.append('%s=<str len%d>' % (kp, len(v)))
            elif isinstance(v, (int, float, bool)) or v is None:
                out.append('%s=%s' % (kp, v))
            else:
                dump(v, kp + '.', out, depth + 1)
    elif isinstance(o, list):
        for i, v in enumerate(o[:4]):
            if isinstance(v, dict):
                dump(v, '%s[%d].' % (prefix, i), out, depth + 1)
            elif isinstance(v, (str, int, float, bool)):
                out.append('%s[%d]=%s' % (prefix, i, str(v)[:120]))
    return out


def list_ns(nsname, q, size=20, tok=b''):
    body = fs(1, nsname) + fv(2, size) + (ns_name_bytes(tok)) + (fs(4, q) if q else b'')
    r = grpc_call(T + 'ListWorkflowExecutions', body, timeout=18)
    rows = []
    nxt = b''
    if r['st'] == '0' and r['data']:
        pl = frame_payload(r['data'])
        nxt = get1(pl, 2) or b''
        for ei in all_of(pl, 1):
            ex = get1(ei, 1) or b''
            rows.append({'wid': (get1(ex, 1) or b'').decode('utf-8', 'replace'),
                         'rid': (get1(ex, 2) or b'').decode('utf-8', 'replace'),
                         'type': (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')})
    return r, rows, nxt


ns_name_bytes = lambda b: (ns['fb'](3, b) if b else b'')


def hist(nsname, wid, rid, pages=3, size=30):
    tok = b''
    evs = []
    for pg in range(pages):
        body = fs(1, nsname) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, size) + (fmsg(4, tok) if tok else b'')
        r = grpc_call(T + 'GetWorkflowExecutionHistory', body, timeout=30)
        if r['st'] != '0' or not r['data']:
            return None, r, pg
        pl = frame_payload(r['data'])
        h = get1(pl, 1) or b''
        tok = get1(pl, 3) or b''
        evs.append(h)
        if not tok:
            break
    return b''.join(evs), None, pg + 1


def extract(h):
    txt = printable_bytes(h)
    ids = sorted(set(IDRE.findall(txt)))
    hosts = sorted(set(HOSTRE.findall(txt)))[:12]
    internal = sorted(set(INTRE.findall(txt)))[:20]
    tqs = sorted(set(re.findall(r'vmr-[A-Za-z0-9._-]+', txt)))[:6]
    objs = jsons_from(h, cap=30)
    return ids, hosts, internal, tqs, objs


p('===I67795-P2 START %s %s===' % (MARK, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))
p('host=' + subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())

r = grpc_call(T + 'GetClusterInfo', b'', timeout=12)
if r['st'] == '0':
    pl = frame_payload(r['data'])
    p('CLUSTER|len=%d|S=%s' % (r['n'], re.sub(r'\s+', ' ', printable_bytes(pl))[:500]))
    p('CLUSTER_HEX=' + pl.hex()[:300])

for n in ['storage-agent', 'vm-runtime', 'blockstore', 'dataplane-stackers', 'dataplane-namespaces']:
    rr = grpc_call(T + 'DescribeNamespace', fs(1, n), timeout=12)
    if rr['st'] == '0' and rr['data']:
        pl = frame_payload(rr['data'])
        p('NSD|%s|len=%d|S=%s' % (n, rr['n'], re.sub(r'\s+', ' ', printable_bytes(pl))[:300]))
        p('   HEX=%s' % pl.hex()[:300])
    for tag, q in [('open', ''), ('Completed', 'ExecutionStatus="Completed"'), ('7d', 'StartTime > "2026-10-13T00:00:00Z"'), ('24h', 'StartTime > "2026-10-19T14:00:00Z"')]:
        cq = grpc_call(T + 'CountWorkflowExecutions', fs(1, n) + (fs(2, q) if q else b''), timeout=10)
        cnum = getv(frame_payload(cq['data']), 1) if (cq['st'] == '0' and cq['data']) else -1
        lr, rows, _ = list_ns(n, q, size=20)
        p('CNT|%s|%s|st=%s|cnt=%s|n=%d' % (n, tag, lr['st'], cnum, len(rows)))

# vm-runtime full pass
lr, rows, nxt = list_ns('vm-runtime', '', size=20)
if nxt:
    lr2, rows2, _ = list_ns('vm-runtime', '', size=20, tok=nxt)
    rows += rows2
p('VMR_ROWS=%d' % len(rows))
seen = set()
shown_create = 0
shown_pull = 0
for e in rows:
    key = e['rid']
    if key in seen:
        continue
    seen.add(key)
    h, err, pgs = hist('vm-runtime', e['wid'], e['rid'], pages=3)
    if h is None:
        p('H2|%s|%s|FAIL|st=%s|pg=%s' % (e['type'][:26], e['wid'][:60], err['st'], pgs))
        continue
    ids, hosts, internal, tqs, objs = extract(h)
    p('H2|%s|%s|evbytes=%d|ids=%s|tq=%s' % (e['type'][:26], e['wid'][:60], len(h),
                                           ','.join(ids)[:220] or '-', ','.join(tqs)[:80] or '-'))
    if hosts:
        p('   HOSTS=' + ','.join(hosts)[:300])
    if internal:
        p('   INT=' + ','.join(internal)[:300])
    if e['type'] == 'CreateVmWorkflow' and shown_create < 1:
        shown_create += 1
        allv = []
        for o in objs:
            dump(o, 'J.', allv)
        # dedupe consecutive
        seenl = set()
        uniq = [x for x in allv if not (x in seenl or seenl.add(x))]
        p('   CREATE_DUMP[%d]:' % len(uniq))
        for ln in uniq[:260]:
            p('    ' + ln[:240])
    elif e['type'] == 'DeleteVmWorkflow' and shown_create < 2:
        shown_create += 1
        allv = []
        for o in objs:
            dump(o, 'D.', allv)
        p('   DELETE_DUMP=' + ' | '.join(allv)[:500])
    elif e['type'].startswith('PullImageLayer') and shown_pull < 2:
        shown_pull += 1
        allv = []
        for o in objs[:1]:
            dump(o, 'P.', allv)
        p('   PULL_DUMP=' + ' | '.join(allv)[:900])

# task queue detail on discovered names
for tq in ['vmr-dpsjc-production-build-server-011', 'vm-runtime', 'vm_runner']:
    rr = grpc_call(T + 'DescribeTaskQueue', fs(1, 'vm-runtime') + fmsg(2, fs(1, tq)) + fv(3, 1) + fv(4, 1) + fv(5, 1), timeout=12)
    txt = re.sub(r'\s+', ' ', printable_bytes(frame_payload(rr['data']))) if (rr['st'] == '0' and rr['data']) else ''
    p('TQD|vm-runtime|%s|st=%s|len=%d|ids=%s|S=%s' % (tq, rr['st'], rr['n'], ','.join(sorted(set(IDRE.findall(txt))))[:200] or '-', txt[:300]))

p('===I67795-P2 END %s===' % MARK)
