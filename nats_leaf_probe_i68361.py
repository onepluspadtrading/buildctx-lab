#!/usr/bin/env python3
# I68361 - NATS 7422 (mtls-service-gateway leafnode listener) determination probe.
# READ-ONLY: one leafnode-form CONNECT without credentials (no lang); never SUB/PUB/HPUB.
# Attempts: at most one no-cert TLS handshake, at most two CONNECT forms (baseline + variant).
import socket, ssl, json, os, subprocess, tempfile, hashlib, time, re

CERT = '/pki/client.crt'; KEY = '/pki/client.key'; CA = '/pki/server-ca-bundle.crt'
HOST = 'external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
PORT = 7422
TAG = 'I68361'


def emit(k, o):
    print('%s|%s|%s' % (TAG, k, json.dumps(o, ensure_ascii=False)), flush=True)


def peer_info(der):
    fn = tempfile.mktemp(suffix='.pem')
    open(fn, 'w').write(ssl.DER_cert_to_PEM_cert(der))
    r = {}
    for k, a in (('subject', ['-subject', '-nameopt', 'RFC2253']),
                 ('issuer', ['-issuer', '-nameopt', 'RFC2253']),
                 ('eku', ['-ext', 'extendedKeyUsage']),
                 ('san', ['-ext', 'subjectAltName']),
                 ('dates', ['-dates'])):
        p = subprocess.run(['openssl', 'x509', '-in', fn, '-noout'] + a,
                           capture_output=True, text=True, timeout=10)
        r[k] = ' '.join(p.stdout.split())[:400]
    p = subprocess.run(['openssl', 'verify', '-CAfile', CA, fn],
                       capture_output=True, text=True, timeout=10)
    r['chain_verify'] = ' '.join((p.stdout + p.stderr).split())[:200]
    r['sha256'] = hashlib.sha256(der).hexdigest()[:32]
    os.unlink(fn)
    return r


def handshake(with_cert):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if with_cert:
        ctx.load_cert_chain(CERT, KEY)
    raw = socket.create_connection((HOST, PORT), timeout=5)
    raw.settimeout(8)
    return ctx.wrap_socket(raw)


def read_info(tls):
    buf = b''
    tls.settimeout(8)
    while b'\r\n' not in buf and len(buf) < 65536:
        d = tls.recv(4096)
        if not d:
            break
        buf += d
    line = buf.split(b'\r\n')[0].decode('utf-8', 'replace')
    return buf, line


def drain(tls, seconds, cap=262144):
    """collect whatever the server sends within `seconds`, return bytes"""
    out = b''
    end = time.time() + seconds
    while time.time() < end and len(out) < cap:
        try:
            tls.settimeout(max(0.3, end - time.time()))
            d = tls.recv(4096)
        except socket.timeout:
            break
        except Exception:
            break
        if not d:
            break
        out += d
    return out


def connect_form(tls, body, label, wait=8):
    payload = b'CONNECT ' + json.dumps(body).encode() + b'\r\n'
    tls.sendall(payload)
    rep = drain(tls, wait)
    txt = rep.decode('utf-8', 'replace')
    return {'label': label, 'sent_json': body, 'reply_len': len(rep),
            'reply_head': txt[:600], 'reply_hex_head': rep[:48].hex()}


def summarise_lsplus(txt):
    subs = re.findall(r'LS\+\s+(\S+)', txt)
    hints = re.findall(r'LS\+\s+\S+\s+(\S+)', txt)
    return {'ls_count': len(subs),
            'ls_prefixes': sorted({'.'.join(s.split('.')[:2]) for s in subs})[:40],
            'ls_sample': subs[:25]}


def main():
    emit('ENV', {'host': socket.gethostname(),
                 'cert_sha': hashlib.sha256(open(CERT, 'rb').read()).hexdigest()[:16],
                 'dest': '%s:%d' % (HOST, PORT)})

    # (a) is the client certificate mandatory?
    a = {}
    try:
        t = handshake(False)
        a['tls'] = 'handshake_ok'
        a['version'] = t.version()
        try:
            t.settimeout(4)
            d = t.recv(64)
            a['recv'] = d[:60].decode('utf-8', 'replace')
        except ssl.SSLError as e:
            a['recv'] = 'SSLError:%s' % str(e)[:120]
        except socket.timeout:
            a['recv'] = 'timeout(no app data readable)'
        except Exception as e:
            a['recv'] = '%s:%s' % (type(e).__name__, str(e)[:120])
        try:
            t.close()
        except Exception:
            pass
    except ssl.SSLError as e:
        a['tls'] = 'SSLError'
        a['err'] = str(e)[:300]
    except Exception as e:
        a['tls'] = '%s:%s' % (type(e).__name__, str(e)[:200])
    emit('NOCERT', a)

    if a.get('tls') not in ('handshake_ok', 'SSLError'):
        emit('FATAL', {'err': 'TCP/TLS unreachable from this vantage (likely non-datapacket builder)', 'detail': a})
        return

    # (b) with pooled stacklet client cert -> INFO
    t = handshake(True)
    ver = t.version()
    pinfo = peer_info(t.getpeercert(binary_form=True))
    buf, line = read_info(t)
    info = {}
    if line.startswith('INFO '):
        try:
            info = json.loads(line[5:])
        except Exception:
            info = {'_raw_head': line[:400]}
    keep = ('server_id', 'server_name', 'version', 'proto', 'go', 'host', 'port', 'headers',
            'auth_required', 'tls_required', 'tls_verify', 'max_payload', 'jetstream',
            'nonce', 'cluster', 'domain', 'compression', 'client_id', 'info_on_connect',
            'leafnode_urls', 'connect_urls', 'ldm')
    emit('HANDSHAKE', {'with_client_cert': True, 'tls': 'ok', 'version': ver,
                       'cipher': t.cipher()[0] if t.cipher() else None,
                       'peer': pinfo,
                       'info': {k: info.get(k) for k in keep if k in info}})

    if not line.startswith('INFO '):
        emit('FATAL', {'err': 'no NATS INFO banner', 'head': line[:300]})
        try:
            t.close()
        except Exception:
            pass
        return

    # (c) exactly one leafnode-form CONNECT, no lang, no credentials
    base = {'verbose': False, 'pedantic': False, 'tls_required': True,
            'name': 'probe', 'protocol': 1}
    r1 = connect_form(t, base, 'leafnode-form-nolang')
    verdict = None
    tail = {}
    if '-ERR' in r1['reply_head']:
        if 'Authorization Violation' in r1['reply_head']:
            verdict = 'NEEDS_LEAFNODE_PASSWORD'
        else:
            verdict = 'OTHER_ERR_BASELINE'
    else:
        # not rejected: accepted as a leaf binding -> ONE PING, read PONG (read-only)
        t.sendall(b'PING\r\n')
        rep = drain(t, 8)
        txt = (r1['reply_head'] + rep.decode('utf-8', 'replace'))
        tail = summarise_lsplus(txt)
        tail['pong'] = 'PONG' in txt
        tail['after_ping_head'] = rep.decode('utf-8', 'replace')[:600]
        verdict = 'LEAFNODE_ACCEPTED_NO_CREDENTIALS'
    try:
        t.close()
    except Exception:
        pass
    emit('CONNECT1', {'result': r1, 'verdict': verdict, 'tail': tail})

    # (d) only if baseline failed with some other -ERR: one variant (drop protocol/verbose/pedantic)
    if verdict == 'OTHER_ERR_BASELINE':
        try:
            t2 = handshake(True)
            _b2, l2 = read_info(t2)
            var = {'version': '2.11.4', 'name': 'probe', 'headers': True}
            r2 = connect_form(t2, var, 'leafnode-form-no-proto-field')
            v2 = 'NEEDS_LEAFNODE_PASSWORD' if 'Authorization Violation' in r2['reply_head'] else \
                 ('OTHER_ERR_VARIANT' if '-ERR' in r2['reply_head'] else 'LEAFNODE_ACCEPTED_NO_CREDENTIALS')
            try:
                t2.close()
            except Exception:
                pass
            emit('CONNECT2', {'result': r2, 'verdict': v2})
            verdict = v2
        except Exception as e:
            emit('CONNECT2', {'err': '%s:%s' % (type(e).__name__, str(e)[:200])})

    emit('FINAL', {'verdict': verdict,
                   'nats': {k: info.get(k) for k in ('server_name', 'version', 'cluster', 'domain',
                                                     'auth_required', 'tls_verify', 'leafnode_urls') if k in info},
                   'tls_version': ver})


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        emit('FATAL', {'err': '%s:%s' % (type(e).__name__, str(e)[:300])})
