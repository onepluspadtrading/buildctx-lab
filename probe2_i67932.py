#!/usr/bin/env python3
# I67932 probe2: per-method mapping control + StartWorkflowExecution judgment + schedule inventory
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
    fu = '/tmp/q%d.bin' % CTR[0]
    hu = '/tmp/qh%d.txt' % CTR[0]
    bu = '/tmp/qb%d.bin' % CTR[0]
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
    return {'st': (sts[-1] if sts else '-'), 'msg': (msgs[-1].strip()[:150] if msgs else ''),
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
        print('  P|' + s[:260], flush=True)
    return r


def wfe(wid, rid=''):
    return fs(1, wid) + (fs(2, rid) if rid else b'')


def start_body(ns, wid, wtype, tq, inp=None):
    b = fs(1, ns) + fs(2, wid) + fmsg(3, fs(1, wtype)) + fmsg(4, fs(1, tq))
    if inp:
        b += fmsg(5, fmsg(1, json.dumps(inp).encode()))  # Payloads{Payload{data=json}}
    b += fs(10, 'i67932-selftest') + fs(11, 'i67932-req-' + TS)
    return b


def term_body(ns, wid, rid):
    return fs(1, ns) + fmsg(2, wfe(wid, rid)) + fs(3, 'i67932-selftest cleanup') + fs(5, 'i67932') + fs(6, rid)


print('===I67932-P2 START=== ' + TS, flush=True)
print('host=%s' % subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(), flush=True)

print('===A PER-METHOD CONTROL===', flush=True)
p1('CTL|BOGUS_METHOD|WS|<empty>', T + 'I67932NoSuchMethodXyz', b'')
p1('CTL|BOGUS_METHOD|WS|ns=builds', T + 'I67932NoSuchMethodXyz', fs(1, 'builds'))
p1('CTL|GetSystemInfo', T + 'GetSystemInfo', b'')
p1('CTL|Count|builds|query=ExecutionStatus="Running"', T + 'CountWorkflowExecutions',
   fs(1, 'builds') + fs(2, 'ExecutionStatus="Running"'))

print('===B START noop type, fake task queue (no worker) ===', flush=True)
for ns in ('builds', 'vm-runtime'):
    wid = 'i67932-noop-%s-%s' % (ns.replace('-', ''), TS)
    r = p1('START|NOOP|' + ns, T + 'StartWorkflowExecution',
           start_body(ns, wid, 'I67932NoopProbe', 'i67932-noop-tq', {'probe': 'i67932', 'ns': ns}))
    rid = ''
    if r['st'] == '0':
        try:
            for f, w, v in parse(payload(r['data'])):
                if f == 1 and w == 2:
                    rid = v.decode()
        except Exception:
            pass
    if rid:
        print('  RUNID|%s|%s' % (wid, rid), flush=True)
        time.sleep(0.8)
        p1('TERMINATE|NOOP|' + ns, T + 'TerminateWorkflowExecution', term_body(ns, wid, rid))
        time.sleep(0.5)
        p1('VERIFY|DESCRIBE|' + ns, T + 'DescribeWorkflowExecution', fs(1, ns) + fmsg(2, wfe(wid, rid)))
    time.sleep(0.6)

print('===C START platform type w/ OWN ids, fake tq (not consumed) ===', flush=True)
wid = 'i67932-ownids-%s' % TS
r = p1('START|ScheduleSnapshotAndBuild|builds|ownIDs', T + 'StartWorkflowExecution',
       start_body('builds', wid, 'ScheduleSnapshotAndBuild', 'i67932-noop-tq', MY))
rid = ''
if r['st'] == '0':
    try:
        for f, w, v in parse(payload(r['data'])):
            if f == 1 and w == 2:
                rid = v.decode()
    except Exception:
        pass
if rid:
    print('  RUNID|%s|%s' % (wid, rid), flush=True)
    time.sleep(0.8)
    p1('TERMINATE|OWNIDS', T + 'TerminateWorkflowExecution', term_body('builds', wid, rid))
    time.sleep(0.4)
    p1('VERIFY|DESCRIBE|OWNIDS', T + 'DescribeWorkflowExecution', fs(1, 'builds') + fmsg(2, wfe(wid, rid)))

print('===D START negative controls ===', flush=True)
p1('NEG|START|nonexistent-ns', T + 'StartWorkflowExecution',
   start_body('i67932-nonexistent-ns', 'i67932-x-' + TS, 'I67932NoopProbe', 'i67932-noop-tq'))
p1('NEG|START|no-wf-type', T + 'StartWorkflowExecution',
   fs(1, 'builds') + fs(2, 'i67932-x2-' + TS) + fmsg(4, fs(1, 'i67932-noop-tq')))

print('===E SCHEDULE INVENTORY (read-only) ===', flush=True)
for ns in ('builds', 'vm-runtime', 'temporal-system', 'dataplane-stackers', 'storage-agent', 'blockstore', 'dataplane-namespaces'):
    r = p1('SCHED|ListSchedules|' + ns, T + 'ListSchedules', fs(1, ns) + fv(2, 5))
    if r['st'] == '0' and r['n'] > 5:
        pl = payload(r['data'])
        try:
            scheds = [v for f, w, v in parse(pl) if f == 1 and w == 2]
            print('  SCHEDN|%s|%d' % (ns, len(scheds)), flush=True)
            for s in scheds[:5]:
                sid = ''
                try:
                    for f, w, v in parse(s):
                        if f == 1 and w == 2:
                            sid = v.decode('utf-8', 'replace')[:70]
                except Exception:
                    pass
                print('   SID|' + sid, flush=True)
        except Exception as e:
            print('  PARSE_ERR|' + repr(e)[:80], flush=True)

print('===F AUTHZ extra: temporal-system Terminate bogus ===', flush=True)
p1('AUTHZ|Terminate|temporal-system', T + 'TerminateWorkflowExecution',
   fs(1, 'temporal-system') + fmsg(2, wfe('i67932-doesnotexist-' + TS, '00000000-0000-0000-0000-000000000000'))
   + fs(3, 'i67932-authprobe') + fs(5, 'i67932'))

print('===G BATCH/SCHED service variants===', flush=True)
p1('SVC|ScheduleService|ListSchedules', '/temporal.api.scheduleservice.v1.ScheduleService/ListSchedules', fs(1, 'builds'))
p1('SVC|BatchService|ListBatchJobs', '/temporal.api.batch.v1.BatchService/ListBatchJobs', fs(1, 'builds'))
p1('SVC|OperatorService|ListSearchAttributes', '/temporal.api.operatorservice.v1.OperatorService/ListSearchAttributes', fs(1, 'builds'))
print('===I67932-P2 END===', flush=True)
