#!/usr/bin/env python3
# i69178: zero-side-effect semantic judgement of orchestrator WRITE methods through the
# external-mtls 443 gateway. Only paths whose handler cannot write on a nonexistent id
# are exercised (DrainStacker=NotFound before Fire, AcknowledgeLoss=no mint,
# StackletHeartbeat=GetStacklet fails before write, ReportStackerStatus(nil)=pure no-op).
# NEVER sends a real stacker id, never drains/updates/creates anything.
import subprocess, struct, json, sys, os, time, re, uuid

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA = '/pki/ca.pem'
CRT = '/pki/client.crt'
KEY = '/pki/client.key'
TS = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
CTR = [0]
P = '/orchestrator.OrchestrationService/'
DC = '/orchestrator.DynamicConfigService/'


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


def payload(b):
    if len(b) >= 5 and b[0] == 0:
        l = struct.unpack('>I', b[1:5])[0]
        return b[5:5 + l]
    return b


def call(name, path, body=b'', timeout=25, insecure=False):
    CTR[0] += 1
    fu = '/tmp/w%d.bin' % CTR[0]
    hu = '/tmp/wh%d.txt' % CTR[0]
    bu = '/tmp/wb%d.bin' % CTR[0]
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    args = ['curl', '-sS', '--http2', '--connect-timeout', '8', '-m', str(timeout), '-D', hu, '-o', bu,
            '--cert', CRT, '--key', KEY]
    args += ['-k'] if insecure else ['--cacert', CA]
    args += ['-X', 'POST', G + path,
             '-H', 'te: trailers', '-H', 'content-type: application/grpc', '--data-binary', '@' + fu]
    t0 = time.time()
    prc = subprocess.run(args, capture_output=True, text=True)
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
    r = {'st': (sts[-1] if sts else '-'), 'msg': (msgs[-1].strip()[:240] if msgs else ''),
         'n': len(data), 'data': data, 'dt': dt, 'rc': prc.returncode,
         'err': (prc.stderr or '').strip()[:200]}
    print('RES|%s|st=%s|rc=%s|dt=%s|n=%d|msg=%s%s' % (
        name, r['st'], r['rc'], r['dt'], r['n'], r['msg'],
        ('|ERR=' + r['err']) if r['rc'] != 0 else ''), flush=True)
    return r


def main():
    print('START|%s|host=%s' % (TS, os.uname().nodename), flush=True)
    try:
        eg = subprocess.run(['curl', '-sS', '-m', '10', 'https://api.ipify.org'],
                            capture_output=True, text=True).stdout.strip()
    except Exception as e:
        eg = 'ERR'
    print('EGRESS_IP|%s' % eg, flush=True)
    print('PKI|ca=%d|crt=%d|key=%d' % (os.path.getsize(CA), os.path.getsize(CRT), os.path.getsize(KEY)), flush=True)

    # 0) positive control (read method, previously proven st=0 through this gateway)
    r = call('Health', P + 'Health', b'')
    insecure = (r['rc'] != 0)
    if insecure:
        print('RETRY_INSECURE|Health', flush=True)
        r = call('Health_k', P + 'Health', b'', insecure=True)
        insecure = True

    time.sleep(3)
    # 1) DrainStacker: handler validates -> GetStacker -> codes.NotFound BEFORE balise Fire.
    sid1 = str(uuid.uuid4())
    body = fs(1, sid1) + fs(2, 'i69178 zero-side-effect probe (nonexistent id)')
    print('SID|DrainStacker|%s' % sid1, flush=True)
    call('DrainStacker', P + 'DrainStacker', body, insecure=insecure)

    time.sleep(3)
    # 2) AcknowledgeLoss: GetStacker swallows NotFound -> Zone="" -> Fire returns ErrInstanceNotFound, no mint.
    sid2 = str(uuid.uuid4())
    body = fs(1, sid2) + fs(2, 'i69178 zero-side-effect probe (nonexistent id)')
    print('SID|AcknowledgeLoss|%s' % sid2, flush=True)
    call('AcknowledgeLoss', P + 'AcknowledgeLoss', body, insecure=insecure)

    time.sleep(3)
    # 3) StackletHeartbeat: GetStacklet(random) fails before any Upsert.
    sid3 = str(uuid.uuid4())
    body = fs(1, sid3)
    print('SID|StackletHeartbeat|%s' % sid3, flush=True)
    call('StackletHeartbeat', P + 'StackletHeartbeat', body, insecure=insecure)

    time.sleep(3)
    # 4) ReportStackerStatus with stacker_status ABSENT = pure no-op branch (returns empty response).
    sid4 = str(uuid.uuid4())
    body = fs(1, sid4)
    print('SID|ReportStackerStatus|%s' % sid4, flush=True)
    call('ReportStackerStatus_nil', P + 'ReportStackerStatus', body, insecure=insecure)

    time.sleep(3)
    # 5) UpdateStacklet with EMPTY stacklet: handler rejects empty id before any upsert (zero write).
    call('UpdateStacklet_emptyid', P + 'UpdateStacklet', b'', insecure=insecure)

    time.sleep(3)
    # 6) read-only live dynamic config: does the manualDrain switch gate DrainStacker right now?
    r = call('GetConfig_stacker_failover', DC + 'GetConfig', fs(1, 'stacker_failover'), insecure=insecure)
    try:
        pl = payload(r['data'])
        entry = None
        for f, w, v in parse(pl):
            if f == 1 and w == 2:
                entry = v
        cj = None
        if entry is not None:
            for f, w, v in parse(entry):
                if f == 3 and w == 2:
                    cj = v.decode('utf-8', 'replace')
        if cj:
            o = json.loads(cj)
            print('DYNCFG|keys=%s|manualDrain=%s|autoFailover=%s|bootAllocationCheckEnabled=%s' % (
                sorted(o.keys()), json.dumps(o.get('manualDrain'))[:200],
                json.dumps(o.get('autoFailover'))[:120], o.get('bootAllocationCheckEnabled')), flush=True)
        else:
            print('DYNCFG|unparsed|len=%d|txt=%s' % (len(pl), pl[:300]), flush=True)
    except Exception as e:
        print('DYNCFG|parse_err|%s' % e, flush=True)
    print('END', flush=True)


if __name__ == '__main__':
    main()
