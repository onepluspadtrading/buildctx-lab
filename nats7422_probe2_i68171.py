#!/usr/bin/env python3
# I68171 probe2 - focused: gateway:7422 read-only NATS leaf handshake.
# Only one CONNECT with NO credentials. No SUB/PUB/HPUB, no credential guessing.
import socket, ssl, json, os, subprocess, tempfile, hashlib, time

PHASE = os.environ.get('PHASE', 'p2')
CERT = '/pki/client.crt'; KEY = '/pki/client.key'; CA = '/pki/server-ca-bundle.crt'
HOST = 'external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
PORT = 7422
TAG = 'I68171P2-%s' % PHASE

def emit(k, o):
    print('%s|%s|%s' % (TAG, k, json.dumps(o, ensure_ascii=False)), flush=True)

def subj(der):
    fn = tempfile.mktemp(suffix='.pem'); open(fn, 'w').write(ssl.DER_cert_to_PEM_cert(der))
    r = {}
    for k, a in (('subject', ['-subject', '-nameopt', 'RFC2253']),
                 ('issuer', ['-issuer', '-nameopt', 'RFC2253']),
                 ('eku', ['-ext', 'extendedKeyUsage']),
                 ('san', ['-ext', 'subjectAltName'])):
        p = subprocess.run(['openssl', 'x509', '-in', fn, '-noout'] + a, capture_output=True, text=True, timeout=10)
        r[k] = ' '.join(p.stdout.split())[:300]
    p = subprocess.run(['openssl', 'verify', '-CAfile', CA, fn], capture_output=True, text=True, timeout=10)
    r['chain_verify'] = ' '.join((p.stdout + p.stderr).split())[:150]
    os.unlink(fn)
    return r

def main():
    emit('ENV', {'phase': PHASE, 'host': socket.gethostname(),
                 'cert_sha': hashlib.sha256(open(CERT, 'rb').read()).hexdigest()[:16]})
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(CERT, KEY)
    raw = socket.create_connection((HOST, PORT), timeout=4); raw.settimeout(8)
    tls = ctx.wrap_socket(raw)
    res = {'tls': 'ok', 'version': tls.version(), 'peer': subj(tls.getpeercert(binary_form=True))}
    buf = b''
    while b'\r\n' not in buf:
        d = tls.recv(4096)
        if not d: break
        buf += d
    line = buf.split(b'\r\n')[0].decode('utf-8', 'replace')
    res['banner_len'] = len(buf)
    info = {}
    if line.startswith('INFO '):
        try:
            info = json.loads(line[5:])
        except Exception as e:
            res['info_err'] = type(e).__name__
    keep = ('server_id', 'server_name', 'version', 'proto', 'go', 'host', 'port', 'headers',
            'auth_required', 'tls_required', 'tls_verify', 'max_payload', 'jetstream', 'client_id',
            'nonce', 'cluster', 'domain', 'compression', 'leafnode_urls', 'ldm', 'xkey')
    res['info'] = {k: info.get(k) for k in keep if k in info}
    res['banner_head'] = line[:120]
    # single CONNECT, no auth fields at all
    payload = b'CONNECT ' + json.dumps({'verbose': False, 'pedantic': False, 'lang': 'probe',
                                        'version': '0.0.1', 'protocol': 1,
                                        'name': 'readonly-i68171', 'tls_required': True,
                                        'headers': True, 'no_responders': True}).encode() + b'\r\n'
    tls.sendall(payload)
    res['connect'] = 'single CONNECT, no user/pass/auth_token'
    reply = b''
    tls.settimeout(8)
    try:
        while len(reply) < 1200:
            d = tls.recv(1024)
            if not d:
                res['eof'] = True; break
            reply += d
            if b'\r\n' in reply:
                break
    except socket.timeout:
        res['reply_timeout'] = True
    res['connect_reply'] = reply.decode('utf-8', 'replace')[:400]
    res['reply_hex_head'] = reply[:40].hex()
    try: tls.close()
    except Exception: pass
    emit('RESULT', res)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        emit('FATAL', {'err': '%s:%s' % (type(e).__name__, str(e)[:200])})
