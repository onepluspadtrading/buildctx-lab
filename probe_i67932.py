#!/usr/bin/env python3
# I67932: Temporal WRITE-method mapping + authz-level probe over external-mtls gateway
# Scope: mapping (empty body -> st12=unmapped / st3=mapped) + bogus-execution authz calls.
# Only actual write: ONE self-owned noop StartWorkflowExecution (immediately Terminated).
import subprocess, struct, json, sys, os, time, re

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/server-ca-bundle.crt'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
MARK = os.environ.get('MARK', 'I67932')
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]
T = '/temporal.api.workflowservice.v1.WorkflowService/'
S = '/temporal.api.workflowservice.v1.ScheduleService/'
B = '/temporal.api.batch.v1.BatchService/'
BOGUS_WID = 'i67932-doesnotexist-' + TS
ZERO_RID = '00000000-0000-0000-0000-000000000000'


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
        if s > 63:
            break
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
            out.append((f, 2, b[i:i + l]))
            i += l
        elif w == 5:
            out.append((f, 5, b[i:i + 4])); i += 4
        elif w == 1:
            out.append((f, 1, b[i:i + 8])); i += 8
        else:
            raise ValueError('wt%d' % w)
    return out


def grpc_call(path, body=b'', timeout=20):
    CTR[0] += 1
    n = CTR[0]
    fu = '/tmp/r%d.bin' % n
    hu = '/tmp/h%d.txt' % n
    bu = '/tmp/b%d.bin' % n
    framed = b'\x00' + struct.pack('>I', len(body)) + body
    open(fu, 'wb').write(framed)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '6', '-m', str(timeout), '-D', hu, '-o', bu,
            '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
            '-H', 'te: trailers', '-H', 'content-type: application/grpc',
            '--data-binary', '@' + fu]
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
    try:
        os.unlink(fu)
    except Exception:
        pass
    return {'http': p.stdout.strip(), 'st': (sts[-1] if sts else '-'),
            'msg': (msgs[-1].strip()[:200] if msgs else ''), 'n': len(data),
            'data': data, 'dt': dt, 'err': (p.stderr or '').strip()[:120]}


def frame_payload(b):
    if len(b) >= 5 and b[0] == 0:
        l = struct.unpack('>I', b[1:5])[0]
        return b[5:5 + l]
    return b


def strs(b, lim=200):
    out = [x.decode('utf-8', 'replace') for x in re.findall(rb'[\x20-\x7e]{3,}', b)]
    return ' | '.join(out)[:lim]


def one(tag, path, body=b''):
    r = grpc_call(path, body)
    print('M|%s|http=%s|st=%s|len=%d|t=%s|msg=%s' % (tag, r['http'], r['st'], r['n'], r['dt'], r['msg']), flush=True)
    if r['n']:
        pl = frame_payload(r['data'])
        if pl:
            print('    B: ' + strs(pl, 300), flush=True)
    return r


def wfe(wid, rid):
    return fs(1, wid) + fs(2, rid)


# request builders: (path, body) with namespace / bogus execution
def build(method, ns):
    if method == 'SignalWorkflowExecution':
        return fs(1, ns) + fmsg(2, wfe(BOGUS_WID, ZERO_RID)) + fs(3, 'i67932-probe') + fs(5, 'i67932') + fs(6, 'i67932-req-' + TS)
    if method == 'SignalWithStartWorkflowExecution':
        return fs(1, ns) + fs(2, BOGUS_WID) + fmsg(3, fs(1, 'I67932NoopProbe')) + fmsg(4, fs(1, 'i67932-noop-tq')) \
            + fs(10, 'i67932-probe') + fs(11, 'i67932') + fs(12, 'i67932-req-' + TS)
    if method == 'UpdateWorkflowExecution':
        return fs(1, ns) + fmsg(2, wfe(BOGUS_WID, ZERO_RID)) + fs(3, ZERO_RID) \
            + fmsg(4, fs(3, 'i67932-req-' + TS))
    if method == 'RequestCancelWorkflowExecution':
        return fs(1, ns) + fmsg(2, wfe(BOGUS_WID, ZERO_RID)) + fs(3, 'i67932') + fs(4, 'i67932-req-' + TS) + fs(5, ZERO_RID)
    if method == 'TerminateWorkflowExecution':
        return fs(1, ns) + fmsg(2, wfe(BOGUS_WID, ZERO_RID)) + fs(3, 'i67932-authprobe') + fs(5, 'i67932') + fs(6, ZERO_RID)
    if method == 'ResetWorkflowExecution':
        return fs(1, ns) + fmsg(2, wfe(BOGUS_WID, ZERO_RID)) + fs(3, 'i67932-authprobe') + fv(4, 1) + fs(5, 'i67932-req-' + TS)
    if method == 'DeleteWorkflowExecution':
        return fs(1, ns) + fmsg(2, wfe(BOGUS_WID, ZERO_RID))
    if method == 'QueryWorkflow':
        return fs(1, ns) + fmsg(2, wfe(BOGUS_WID, ZERO_RID)) + fmsg(3, fs(1, 'i67932-noop-query'))
    if method == 'StartWorkflowExecution':
        return fs(1, ns) + fs(2, BOGUS_WID) + fmsg(3, fs(1, 'I67932NoopProbe')) + fmsg(4, fs(1, 'i67932-noop-tq')) \
            + fs(10, 'i67932') + fs(11, 'i67932-req-' + TS)
    if method == 'CountWorkflowExecutions':
        return fs(1, ns)
    if method == 'ListSchedules':
        return fs(1, ns) + fv(2, 10)
    if method == 'CreateSchedule':
        return fs(1, ns)
    return fs(1, ns)


print('===I67932 PROBE START %s=== %s' % (MARK, TS), flush=True)
print('host=%s cert=%s' % (subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(),
                           subprocess.run(['sh', '-c', 'openssl x509 -in %s -noout -subject 2>&1' % CRT],
                                          capture_output=True, text=True).stdout.strip()), flush=True)

print('===A CONTROLS===', flush=True)
one('CTL_GetSystemInfo', T + 'GetSystemInfo')
one('CTL_GetSearchAttributes', T + 'GetSearchAttributes')
one('CTL_CountWorkflowExecutions|builds', T + 'CountWorkflowExecutions', build('CountWorkflowExecutions', 'builds'))
one('CTL_CountWorkflowExecutions|vm-runtime', T + 'CountWorkflowExecutions', build('CountWorkflowExecutions', 'vm-runtime'))
one('CTL_ListNamespaces', T + 'ListNamespaces')

WRITE = ['StartWorkflowExecution', 'SignalWorkflowExecution', 'SignalWithStartWorkflowExecution',
         'UpdateWorkflowExecution', 'RequestCancelWorkflowExecution', 'TerminateWorkflowExecution',
         'ResetWorkflowExecution', 'DeleteWorkflowExecution', 'QueryWorkflow',
         'CreateSchedule', 'ListSchedules', 'UpdateSchedule', 'DeleteSchedule']

print('===B MAPPING (empty body) ===', flush=True)
mapped = {}
for m in WRITE:
    for pfx in (T, S):
        if pfx == T and m in ('ListSchedules',):  # also test WorkflowService schedule RPCs
            pass
        r = one('MAP|%s%s|<empty>' % ('WS' if pfx == T else 'SCHED', m), pfx + m, b'')
        if r['st'] != '12' and r['http'] not in ('000', ''):
            mapped[(pfx, m)] = True

print('===C SCHEDULE/BATCH ALT PATHS ===', flush=True)
one('MAP|SCHED|CreateSchedule|<empty>', S + 'CreateSchedule', b'')
one('MAP|SCHED|ListSchedules|builds', S + 'ListSchedules', build('ListSchedules', 'builds'))
one('MAP|BATCH|BatchOperation|<empty>', B + 'BatchOperation', b'')

print('===D NAMESPACE RESOLUTION (ns only) ===', flush=True)
for ns in ('builds', 'vm-runtime', 'i67932-nonexistent-ns'):
    for m in ('TerminateWorkflowExecution', 'RequestCancelWorkflowExecution',
              'SignalWorkflowExecution', 'ResetWorkflowExecution', 'DeleteWorkflowExecution',
              'UpdateWorkflowExecution', 'QueryWorkflow'):
        r = one('NSRES|%s|%s' % (m, ns), T + m, build(m, ns))

print('===E AUTHZ (bogus execution, real namespaces) ===', flush=True)
AUTHZ = ['TerminateWorkflowExecution', 'RequestCancelWorkflowExecution', 'SignalWorkflowExecution',
         'ResetWorkflowExecution', 'DeleteWorkflowExecution', 'UpdateWorkflowExecution', 'QueryWorkflow']
for ns in ('builds', 'vm-runtime'):
    for m in AUTHZ:
        r = one('AUTHZ|%s|%s' % (m, ns), T + m, build(m, ns))
        time.sleep(0.4)

print('===F SCHEDULE READ-ONLY LIST ===', flush=True)
for ns in ('builds', 'vm-runtime'):
    one('SCHEDLIST|WS|%s' % ns, T + 'ListSchedules', build('ListSchedules', ns))
    one('SCHEDLIST|SCHEDSVC|%s' % ns, S + 'ListSchedules', build('ListSchedules', ns))
    time.sleep(0.3)

print('===G START MINIMAL SELF-OWNED (noop type, then terminate) ===', flush=True)
# only if mapped: empty-body st != 12
sm = grpc_call(T + 'StartWorkflowExecution', b'')
print('MAPGATE|StartWorkflowExecution|st=%s|http=%s|msg=%s' % (sm['st'], sm['http'], sm['msg']), flush=True)
if sm['st'] not in ('12', '-') and sm['http'] == '200':
    for ns_ in ('builds', 'vm-runtime'):
        wid = 'i67932-selftest-%s-%s' % (ns_.replace('-', ''), TS)
        body = fs(1, ns_) + fs(2, wid) + fmsg(3, fs(1, 'I67932NoopProbe')) + fmsg(4, fs(1, 'i67932-noop-tq')) \
            + fmsg(7, fv(1, 20)) + fs(10, 'i67932-selftest') + fs(11, 'i67932-selftest-' + TS)
        r = grpc_call(T + 'StartWorkflowExecution', body)
        rid = ''
        if r['st'] == '0':
            pl = frame_payload(r['data'])
            try:
                for f, w, v in parse(pl):
                    if f == 1 and w == 2:
                        rid = v.decode()
            except Exception:
                pass
            print('START_OK|ns=%s|wid=%s|runid=%s' % (ns_, wid, rid), flush=True)
        else:
            print('START|ns=%s|st=%s|http=%s|msg=%s|B=%s' % (ns_, r['st'], r['http'], r['msg'],
                  strs(frame_payload(r['data']), 200) if r['n'] else ''), flush=True)
        if rid:
            time.sleep(1)
            body = fs(1, ns_) + fmsg(2, fs(1, wid) + fs(2, rid)) + fs(3, 'i67932-selftest cleanup') + fs(5, 'i67932') + fs(6, rid)
            one('CLEANUP_Terminate|' + ns_, T + 'TerminateWorkflowExecution', body)
        time.sleep(0.6)
else:
    print('START_NOT_MAPPED_skip', flush=True)

print('===I67932 PROBE END===', flush=True)
