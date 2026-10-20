#!/usr/bin/env python3
# i68429: exhaustive mTLS gateway route-table verification (read-only; one probe per prefix, >=5s apart)
import subprocess, struct, os, re, sys, time

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CRT = '/pki/client.crt'; KEY = '/pki/client.key'; CA = '/pki/server-ca-bundle.crt'

def frame(payload=b''):
    return b'\x00' + struct.pack('>I', len(payload)) + payload

def call(path, t=25):
    open('/tmp/req.bin','wb').write(frame())
    r = subprocess.run(['curl','-sS','--http2','--connect-timeout','8','-m',str(t),
        '-o','/tmp/body.bin','-D','/tmp/hdr.txt','-w','%{http_code} %{remote_ip}',
        '--cert',CRT,'--key',KEY,'--cacert',CA,'-X','POST', G+path,
        '-H','te: trailers','-H','content-type: application/grpc',
        '--data-binary','@/tmp/req.bin'], capture_output=True, text=True)
    body = open('/tmp/body.bin','rb').read() if os.path.exists('/tmp/body.bin') else b''
    hdr = open('/tmp/hdr.txt','rb').read().decode('utf-8','replace') if os.path.exists('/tmp/hdr.txt') else ''
    st = re.findall(r'grpc-status:\s*(\d+)', hdr, re.I)
    msg = re.findall(r'grpc-message:\s*([^\r\n]*)', hdr, re.I)
    up = re.findall(r'x-envoy-upstream-service-time:\s*(\d+)', hdr, re.I)
    srv = re.findall(r'(?im)^server:\s*(\S+)', hdr)
    return {'curl': (r.stdout or '').strip(), 'err': (r.stderr or '').strip()[:200], 'hdl': hdr,
            'http': (r.stdout or '').split(' ')[0], 'ip': (r.stdout or '').split(' ')[1] if ' ' in (r.stdout or '') else '',
            'grpc': st[-1] if st else None, 'gmsg': (msg[-1].strip() if msg else ''),
            'upstream_ms': up[-1] if up else None, 'server': srv[0] if srv else None,
            'body_len': len(body), 'body': body[:120]}

PROBES = [
 ('CTRL orchestrator.OrchestrationService/Health', '/orchestrator.OrchestrationService/Health'),
 ('CTRL temporal.WorkflowService/GetSystemInfo', '/temporal.api.workflowservice.v1.WorkflowService/GetSystemInfo'),
 ('CTRL orchestrator.DynamicConfigService/GetConfig (exact-path rule)', '/orchestrator.DynamicConfigService/GetConfig'),
 ('RTE grpc.health.v1.Health/Check', '/grpc.health.v1.Health/Check'),
 ('RTE monitoring_pipe.MonitoringPipeService/NoSuchMethod', '/monitoring_pipe.MonitoringPipeService/NoSuchMethod'),
 ('BASE zzz.nonexistent.NopeService/Ping (no-route baseline)', '/zzz.nonexistent.NopeService/Ping'),
 ('NO vm_runner.RunnerApi/GetSystemInfo', '/vm_runner.RunnerApi/GetSystemInfo'),
 ('NO build_ext.BuildAgentApi/GetSystemInfo', '/build_ext.BuildAgentApi/GetSystemInfo'),
 ('NO metalcp.MetalControlPlane/Health', '/metalcp.MetalControlPlane/Health'),
 ('NO storage.StorageService/Health', '/storage.StorageService/Health'),
 ('NO registry_metal.RegistryMetal/Health', '/registry_metal.RegistryMetal/Health'),
 ('NO conductor.ConductorService/Health', '/conductor.ConductorService/Health'),
 ('NO l4lb.L4LBService/List', '/l4lb.L4LBService/List'),
 ('NO network_cp.CertificateService/ListCertificates', '/network_cp.CertificateService/ListCertificates'),
 ('NO orchestrator.DynamicConfigService/UpdateConfig (must be unrouted)', '/orchestrator.DynamicConfigService/UpdateConfig'),
 ('NORM /orchestrator.OrchestrationService/../zzz.nonexistent.Nope/Ping', '/orchestrator.OrchestrationService/../zzz.nonexistent.Nope/Ping'),
]

print('PROBE_HOST', os.uname().nodename, flush=True)
try:
    print('HOSTNAME', open('/etc/hostname').read().strip(), flush=True)
except Exception as e:
    print('HOSTNAME_ERR', e, flush=True)
for f in ('/etc/resolv.conf',):
    try: print('FILE', f, open(f).read().replace('\n',' | ')[:300], flush=True)
    except Exception: pass
print('CERT_EXISTS', os.path.exists(CRT), os.path.exists(KEY), os.path.exists(CA), flush=True)

try:
    o = subprocess.run(['openssl','s_client','-connect','external-mtls-service-gateway-us-west1.gcp.production.rlwy.net:443',
        '-cert',CRT,'-key',KEY,'-CAfile',CA,'-servername','external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'],
        input=b'', capture_output=True, timeout=20)
    txt = o.stdout.decode('utf-8','replace')
    for ln in txt.splitlines():
        if re.search(r'Verify return code|subject=|issuer=|Protocol|Cipher is', ln): print('TLS', ln.strip(), flush=True)
except Exception as e:
    print('TLS_ERR', repr(e), flush=True)

for name, path in PROBES:
    try:
        r = call(path)
    except Exception as e:
        print('RESULT', name, 'EXC', repr(e), flush=True); time.sleep(5); continue
    print('RESULT|%s|path=%s|http=%s|ip=%s|grpc=%s|upstream_ms=%s|server=%s|blen=%d|msg=%s|curl=%s' % (
        name, path, r['http'], r['ip'], r['grpc'], r['upstream_ms'], r['server'], r['body_len'],
        r['gmsg'][:80], r['curl'][:40]), flush=True)
    if r['body_len']:
        print('  BODYHEX', r['body'].hex()[:160], flush=True)
    time.sleep(5)

print('PROBE_DONE', flush=True)
