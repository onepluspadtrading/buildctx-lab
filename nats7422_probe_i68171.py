#!/usr/bin/env python3
# I68171 - read-only NATS leaf(7422) reachability + TLS + INFO + single no-credential CONNECT probe.
# Strictly read-only: no SUB/PUB/HPUB, no credential guessing, one CONNECT without auth only.
import socket, ssl, json, os, sys, subprocess, time, tempfile, hashlib

PHASE = os.environ.get('PHASE', 'build')
CERT = '/pki/client.crt'
KEY = '/pki/client.key'
CA = '/pki/server-ca-bundle.crt'
TIMEOUT = 3.0
GAP = 5.0
TAG = 'I68171-%s' % PHASE

TARGETS = [
    ('n0-pub', 'external-nats-node-us-west1-0.gcp.production.rlwy.net', 7422),
    ('n1-pub', 'external-nats-node-us-west1-1.gcp.production.rlwy.net', 7422),
    ('n2-pub', 'external-nats-node-us-west1-2.gcp.production.rlwy.net', 7422),
    ('n3-pub', 'external-nats-node-us-west1-3.gcp.production.rlwy.net', 7422),
    ('n4-pub', 'external-nats-node-us-west1-4.gcp.production.rlwy.net', 7422),
    ('gw-7422', 'external-mtls-service-gateway-us-west1.gcp.production.rlwy.net', 7422),
    ('n-int', 'internal-nats-nodes-us-west1.gcp.production.rlwy.net', 7422),
    ('n0-4222-control', 'external-nats-node-us-west1-0.gcp.production.rlwy.net', 4222),
]

def emit(kind, obj):
    print('%s|%s|%s' % (TAG, kind, json.dumps(obj, ensure_ascii=False)[:1800]), flush=True)

def resolve(host):
    try:
        return sorted(set(x[4][0] for x in socket.getaddrinfo(host, None, socket.AF_INET)))
    except Exception as e:
        return 'DNS_ERR:%s' % type(e).__name__

def tcp(ip, port):
    t0 = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=TIMEOUT)
        ms = int((time.time() - t0) * 1000)
        return s, 'open', ms
    except socket.timeout:
        return None, 'timeout', int((time.time() - t0) * 1000)
    except ConnectionRefusedError:
        return None, 'refused', int((time.time() - t0) * 1000)
    except Exception as e:
        return None, '%s:%s' % (type(e).__name__, getattr(e, 'errno', '')), int((time.time() - t0) * 1000)

def peer_info(der):
    if not der:
        return {}
    pem = ssl.DER_cert_to_PEM_cert(der)
    fn = tempfile.mktemp(suffix='.pem')
    open(fn, 'w').write(pem)
    out = {}
    for k, a in (('subject', ['-subject', '-nameopt', 'RFC2253']),
                 ('issuer', ['-issuer', '-nameopt', 'RFC2253']),
                 ('eku', ['-ext', 'extendedKeyUsage']),
                 ('san', ['-ext', 'subjectAltName']),
                 ('dates', ['-dates'])):
        try:
            p = subprocess.run(['openssl', 'x509', '-in', fn, '-noout'] + a,
                               capture_output=True, text=True, timeout=10)
            out[k] = ' '.join(p.stdout.split())[:400]
        except Exception as e:
            out[k] = 'ERR:%s' % type(e).__name__
    # local chain verification against the pooled server CA bundle (offline)
    try:
        p = subprocess.run(['openssl', 'verify', '-CAfile', CA, fn], capture_output=True, text=True, timeout=10)
        out['chain_verify'] = (' '.join((p.stdout + p.stderr).split()))[:300]
    except Exception as e:
        out['chain_verify'] = 'ERR:%s' % type(e).__name__
    try:
        out['sha256'] = hashlib.sha256(der).hexdigest()[:32]
    except Exception:
        pass
    os.unlink(fn)
    return out

def handshake(ip, port, with_cert):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
    except Exception:
        pass
    if with_cert:
        ctx.load_cert_chain(CERT, KEY)
    raw = socket.create_connection((ip, port), timeout=TIMEOUT)
    raw.settimeout(6)
    res = {'with_client_cert': with_cert}
    try:
        tls = ctx.wrap_socket(raw, server_hostname=None)
        res['tls'] = 'ok'
        res['version'] = tls.version()
        res['cipher'] = tls.cipher()[0] if tls.cipher() else ''
        res['peer'] = peer_info(tls.getpeercert(binary_form=True))
        # read server banner (NATS INFO or anything else) without sending anything
        try:
            tls.settimeout(5)
            data = tls.recv(4096)
            res['banner_len'] = len(data)
            txt = data.decode('utf-8', 'replace')
            res['banner_head'] = txt[:600]
            if txt.startswith('INFO '):
                try:
                    res['info'] = json.loads(txt[5:].split('\r\n')[0].split('\n')[0])
                except Exception as e:
                    res['info_parse'] = type(e).__name__
            # single CONNECT without any credential (no user/pass/auth_token)
            if res.get('info') is not None:
                payload = b'CONNECT ' + json.dumps({
                    'verbose': False, 'pedantic': False, 'lang': 'py-i68171',
                    'version': '0.0.1', 'protocol': 1, 'name': 'readonly-probe-i68171',
                    'tls_required': True,
                }).encode() + b'\r\n'
                tls.sendall(payload)
                res['connect_sent'] = 'no-auth (no user/pass/auth_token)'
                try:
                    r = tls.recv(4096)
                    res['connect_reply'] = r.decode('utf-8', 'replace')[:600]
                except socket.timeout:
                    res['connect_reply'] = 'TIMEOUT(no reply)'
        except socket.timeout:
            res['banner'] = 'TIMEOUT(no banner)'
        except Exception as e:
            res['banner'] = 'ERR:%s:%s' % (type(e).__name__, str(e)[:200])
        try:
            tls.close()
        except Exception:
            pass
    except ssl.SSLError as e:
        res['tls'] = 'SSLError:%s' % (str(e)[:200],)
    except Exception as e:
        res['tls'] = '%s:%s' % (type(e).__name__, str(e)[:200])
    try:
        raw.close()
    except Exception:
        pass
    return res

def main():
    emit('ENV', {'phase': PHASE, 'hostname': socket.gethostname(),
                 'cert_sha256': hashlib.sha256(open(CERT, 'rb').read()).hexdigest()[:16] if os.path.exists(CERT) else 'MISSING',
                 'ca_exists': os.path.exists(CA), 'key_exists': os.path.exists(KEY),
                 'resolv': open('/etc/resolv.conf').read()[:300] if os.path.exists('/etc/resolv.conf') else ''})
    results = []
    for name, host, port in TARGETS:
        ips = resolve(host)
        rec = {'target': name, 'host': host, 'port': port, 'ips': ips}
        ip = ips[0] if isinstance(ips, list) and ips else None
        if not ip:
            rec['tcp'] = 'NO_DNS'
            emit('TARGET', rec); results.append(rec); continue
        # attempt 1: with pooled stacklet client cert
        s, state, ms = tcp(ip, port)
        rec['tcp'] = state
        rec['tcp_ms'] = ms
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
            time.sleep(0.4)
            rec['tls_client_cert'] = handshake(ip, port, True)
        else:
            rec['tls_client_cert'] = 'skipped(tcp closed)'
        # attempt 2: baseline without client cert (proves whether a client cert is mandatory)
        time.sleep(GAP)
        rec['tls_no_client_cert'] = handshake(ip, port, False)
        emit('TARGET', rec)
        results.append(rec)
        time.sleep(GAP)
    emit('DONE', {'phase': PHASE, 'n': len(results)})

def last_needs_baseline(tc):
    if not isinstance(tc, dict):
        return False
    t = str(tc.get('tls', ''))
    return t.startswith('SSLError') or 'CERTIFICATE_REQUIRED' in t.upper()

if __name__ == '__main__':
    main()
