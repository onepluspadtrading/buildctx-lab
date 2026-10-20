#!/usr/bin/env python3
# I67887: 10.20.0.0/16 reachability probe from build/tenant netns
import os, socket, subprocess, sys, time, random, json

MARK = os.environ.get('MARK', 'I67887')


def sh(cmd, t=12):
    try:
        r = subprocess.run(['sh', '-c', cmd], capture_output=True, timeout=t)
        return (r.stdout + r.stderr).decode('utf-8', 'replace').strip()
    except Exception as e:
        return 'EXC ' + repr(e)


def tcp(ip, port, timeout=3.0):
    t0 = time.time()
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        r = 'OPEN %.2f' % (time.time() - t0)
    except socket.timeout:
        r = 'TIMEOUT %.2f' % (time.time() - t0)
    except ConnectionRefusedError:
        r = 'REFUSED %.2f' % (time.time() - t0)
    except OSError as e:
        r = 'ERR %s %.2f' % (e.__class__.__name__ + ':' + str(e)[:40], time.time() - t0)
    finally:
        s.close()
    return r


def main():
    print('=== %s START host=%s' % (MARK, socket.gethostname()), flush=True)
    print('--- id: ' + sh('id'), flush=True)
    print('--- ip addr:\n' + sh('ip -br addr 2>/dev/null || cat /proc/net/fib_trie | head -40'), flush=True)
    print('--- ip route:\n' + sh('ip route 2>/dev/null; echo ROUTE6; ip -6 route 2>/dev/null | head -5'), flush=True)
    print('--- /proc/net/route:\n' + sh('cat /proc/net/route'), flush=True)
    print('--- resolv:\n' + sh('cat /etc/resolv.conf'), flush=True)
    print('--- hosts:\n' + sh('cat /etc/hosts'), flush=True)
    for dst in ['10.20.130.15', '10.20.25.140', '10.20.78.142', '10.20.0.1', '10.0.0.1']:
        print('--- routeget %s: %s' % (dst, sh('ip route get %s 2>&1' % dst, 5)), flush=True)

    ips = ['10.20.130.15', '10.20.25.140', '10.20.78.142']
    res = {}
    # pass 1/2 on 7235
    for attempt in (1, 2):
        for ip in ips:
            k = '%s:7235#%d' % (ip, attempt)
            v = tcp(ip, 7235, 3.0)
            res[k] = v
            print('TCP %s -> %s' % (k, v), flush=True)
            time.sleep(5 + random.random() * 2)
    # other ports, one shot each
    for ip in ips:
        for p in (7233, 8080, 8081, 9090, 443, 22):
            k = '%s:%d' % (ip, p)
            v = tcp(ip, p, 2.5)
            res[k] = v
            print('TCP %s -> %s' % (k, v), flush=True)
            time.sleep(random.uniform(0.2, 0.8))

    open_any = [k for k, v in res.items() if v.startswith('OPEN')]
    print('OPEN_SET ' + json.dumps(open_any), flush=True)

    if open_any:
        for k in open_any:
            ip, pp = k.split('#')[0].split(':')
            port = int(pp)
            # plain HTTP/1.1 probe
            print('--- HTTP1 %s:%d: ' % (ip, port) + sh(
                "curl -sS -m 5 -D - -o /dev/null http://%s:%d/ 2>&1 | head -20" % (ip, port), 10), flush=True)
            # TLS probe
            print('--- TLS %s:%d: ' % (ip, port) + sh(
                "echo | timeout 6 openssl s_client -connect %s:%d -servername temporal-frontend 2>&1 | "
                "grep -E 'Protocol|Cipher|Verify return|subject=|issuer=|alert' | head -8" % (ip, port), 12), flush=True)
            # gRPC health (plaintext h2c)
            print('--- gRPC health %s:%d: ' % (ip, port) + grpc_call(ip, port,
                '/grpc.health.v1.Health/Check'), flush=True)
            print('--- gRPC GetSystemInfo %s:%d: ' % (ip, port) + grpc_call(ip, port,
                '/temporal.api.workflowservice.v1.WorkflowService/GetSystemInfo'), flush=True)
            # gRPC health over TLS (with stacklet cert)
            print('--- gRPC TLS health %s:%d: ' % (ip, port) + grpc_call(ip, port,
                '/grpc.health.v1.Health/Check', tls=True), flush=True)
    print('=== %s DONE' % MARK, flush=True)


def grpc_call(ip, port, path, tls=False):
    # empty protobuf message frame: 0x00 + len 0
    open('/tmp/frame.bin', 'wb').write(b'\x00\x00\x00\x00\x00')
    tag = (path.replace('/', '_')[:40] or 'x') + ('T' if tls else '')
    hf = '/tmp/h.' + tag
    bf = '/tmp/b.' + tag
    if tls:
        cmd = ("curl -sS -m 8 --http2 -D " + hf + " -o " + bf + " "
               "--cacert /pki/server-ca-bundle.crt --cert /pki/client.crt --key /pki/client.key ")
        url = 'https://%s:%d%s' % (ip, port, path)
    else:
        cmd = ("curl -sS -m 8 --http2-prior-knowledge -D " + hf + " -o " + bf + " ")
        url = 'http://%s:%d%s' % (ip, port, path)
    cmd += ("-H 'content-type: application/grpc' -H 'te: trailers' --data-binary @/tmp/frame.bin " + url +
            "; echo; echo HEADERS; cat " + hf + " | tr -d '\\r' | head -20; "
            "echo; echo BODYHEX; xxd -p " + bf + " 2>/dev/null | head -3")
    return sh(cmd, 20)


if __name__ == '__main__':
    main()
