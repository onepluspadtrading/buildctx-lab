import socket, subprocess, sys, time, os

tag = sys.argv[1] if len(sys.argv) > 1 else "unknown"
print("MARK-I68197-MESH-%s" % tag, flush=True)


def sh(c):
    try:
        return subprocess.check_output(c, shell=True, stderr=subprocess.STDOUT, timeout=8).decode("utf-8", "replace")[:1200]
    except Exception as e:
        return "ERR " + repr(e)


print("HOST", socket.gethostname(), flush=True)
print("ADDR", sh("ip -4 addr 2>/dev/null | grep inet"), flush=True)
print("ROUTE", sh("ip route 2>/dev/null"), flush=True)
print("RESOLV", sh("cat /etc/resolv.conf 2>/dev/null | tr '\\n' '|'"), flush=True)
print("HOSTS", sh("cat /etc/hosts 2>/dev/null | tr '\\n' '|'"), flush=True)

names = [
    "network-cp-discovery.gcp.production.rlwy.net",
    "network-cp-discovery.gcp.staging.rlwy.net",
    "api-server.network-cp.svc",
    "network-cp-dns",
    "network-cp-discovery",
]
for n in names:
    try:
        ip = socket.gethostbyname(n)
        print("DNS", n, ip, flush=True)
        try:
            ips = sorted(set(i[4][0] for i in socket.getaddrinfo(n, None)))
            print("DNSALL", n, ",".join(ips), flush=True)
        except Exception:
            pass
    except Exception as e:
        print("DNS", n, "FAIL", type(e).__name__, flush=True)

targets = [
    ("10.10.10.3", 8449),   # network-cp discovery ILB (prod)
    ("10.10.10.3", 8447),   # dns/rpc port on same ILB
    ("10.10.10.3", 8442),   # api-server port on same ILB
    ("10.10.10.3", 443),
    ("10.10.10.11", 8449),  # staging discovery ILB
    ("10.10.10.42", 8775),  # orchestrator internal (control)
    ("10.10.10.12", 50051), # router internal
    ("network-cp-discovery.gcp.production.rlwy.net", 8449),
]
for h, p in targets:
    t0 = time.time()
    try:
        s = socket.create_connection((h, p), timeout=3)
        print("TCP", h, p, "OPEN", s.getpeername(), flush=True)
        try:
            s.settimeout(2)
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            d = s.recv(64)
            print("TCPBANNER", h, p, d[:32].hex(), flush=True)
        except Exception as e:
            print("TCPBANNER", h, p, "noresp", type(e).__name__, flush=True)
        s.close()
    except Exception as e:
        print("TCP", h, p, "FAIL", type(e).__name__, str(e)[:40], "%.1fs" % (time.time() - t0), flush=True)
    time.sleep(1)

# UDP wireguard listen-port probe: send one junk datagram, note send result only.
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    n = u.sendto(b"\x01" * 148, ("10.10.10.3", 30200))
    print("UDP10.10.10.3:30200 SENT", n, flush=True)
    try:
        d, a = u.recvfrom(256)
        print("UDP REPLY", a, d[:16].hex(), flush=True)
    except Exception as e:
        print("UDP 10.10.10.3:30200 NOREPLY", type(e).__name__, flush=True)
    u.close()
except Exception as e:
    print("UDP FAIL", repr(e), flush=True)

print("DONE-I68197-%s" % tag, flush=True)
