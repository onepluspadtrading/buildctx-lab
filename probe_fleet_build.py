#!/usr/bin/env python3
# i68245: fleet enumeration through external-mtls gateway (read-only).
# Methods: Health, ListStackerHealth, GetStackletConfig, GetDrainStatus. No write/stream RPC.
import subprocess, struct, os, sys, re, json, time, base64, zlib, hashlib

G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CRT = '/pki/client.crt'; KEY = '/pki/client.key'; CA = '/pki/server-ca-bundle.crt'
MARK = 'MARK-I68245-fleet-a1b2'
CTR = [0]

def v(n):
    o = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        if n: o.append(b | 0x80)
        else: o.append(b); return bytes(o)

def fb(f, b): return v((f << 3) | 2) + v(len(b)) + b

def rd(b, i):
    r = 0; s = 0
    while i < len(b):
        x = b[i]; r |= (x & 0x7f) << s; i += 1
        if not x & 0x80: return r, i
        s += 7
    raise ValueError('truncated varint')

def parse(b):
    i = 0; o = []
    while i < len(b):
        k, i = rd(b, i); f = k >> 3; w = k & 7
        if w == 0:
            x, i = rd(b, i); o.append((f, 0, x))
        elif w == 2:
            l, i = rd(b, i)
            if i + l > len(b): raise ValueError('len')
            o.append((f, 2, b[i:i+l])); i += l
        elif w == 5:
            o.append((f, 5, b[i:i+4])); i += 4
        elif w == 1:
            o.append((f, 1, b[i:i+8])); i += 8
        else: raise ValueError('wt%d' % w)
    return o

def dec(b):
    try: return b.decode('utf-8', 'replace')
    except Exception: return b.hex()

def call(path, body=b'', t=120):
    CTR[0] += 1; n = CTR[0]
    fu = '/tmp/f%d' % n; hu = '/tmp/h%d' % n; bu = '/tmp/b%d' % n; tu = '/tmp/t%d' % n
    open(fu, 'wb').write(b'\x00' + struct.pack('>I', len(body)) + body)
    a = ['curl', '-sS', '--http2', '--connect-timeout', '8', '-m', str(t),
         '-D', hu, '-o', bu, '--trace-ascii', tu, '-w', '%{http_code}',
         '--cert', CRT, '--key', KEY, '--cacert', CA, '-X', 'POST', G + path,
         '-H', 'te: trailers', '-H', 'content-type: application/grpc',
         '--data-binary', '@' + fu]
    q = subprocess.run(a, capture_output=True, text=True)
    data = open(bu, 'rb').read() if os.path.exists(bu) else b''
    tr = open(tu, 'rb').read().decode('utf-8', 'replace') if os.path.exists(tu) else ''
    hd = open(hu, 'rb').read().decode('utf-8', 'replace') if os.path.exists(hu) else ''
    st = re.findall(r'grpc-status:\s*(\d+)', tr, re.I) or re.findall(r'grpc-status:\s*(\d+)', hd, re.I)
    msg = re.findall(r'grpc-message:\s*([^\r\n]*)', tr, re.I) or re.findall(r'grpc-message:\s*([^\r\n]*)', hd, re.I)
    pay = b''; i = 0
    while i + 5 <= len(data):
        if data[i] != 0: break
        l = struct.unpack('>I', data[i+1:i+5])[0]
        pay += data[i+5:i+5+l]; i += 5 + l
    return q.stdout.strip(), (int(st[-1]) if st else None), (msg[-1].strip() if msg else ''), pay

def h16(s): return hashlib.sha256(s.encode()).hexdigest()[:16]

def parse_health_row(b):
    d = {}; pending = []
    for f, w, x in parse(b):
        if w == 2:
            if f == 9: pending.append(dec(x))
            else: d[f] = dec(x)
        elif w == 0: d[f] = x
    return d, pending

def parse_zone(b):
    d = {}; contrib = []
    for f, w, x in parse(b):
        if w == 2:
            if f == 4: contrib.append(dec(x))
            else: d[f] = dec(x)
        elif w == 0: d[f] = x
    return d, contrib

def parse_placement(b):
    d = {}
    for f, w, x in parse(b):
        if w == 2: d[f] = dec(x)
        elif w == 0: d[f] = x
    return d

def zchunks(tag, obj):
    raw = json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode()
    comp = zlib.compress(raw, 9)
    b = base64.b64encode(comp).decode()
    print('%s_RAW %d %d %d' % (tag, len(raw), len(comp), len(b)), flush=True)
    step = 700
    for i in range(0, len(b), step):
        print('%s|%04d|%s' % (tag, i // step, b[i:i+step]), flush=True)

def lh(zone, t):
    return call('/orchestrator.OrchestrationService/ListStackerHealth', fb(1, zone.encode()), t=t)

def do_lh(zone, t):
    h, st, msg, pay = lh(zone, t)
    rows = []; zones = []
    try:
        for f, w, x in parse(pay):
            if w == 2 and f == 1: rows.append(parse_health_row(x))
            elif w == 2 and f == 2: zones.append(parse_zone(x))
    except Exception as e:
        print('ZQ|%s|PARSE_ERR|%r' % (zone, e), flush=True)
    print('ZQ|%s|http=%s|st=%s|msg=%s|paylen=%d|rows=%d|zones=%d' % (
        zone or 'ALL', h, st, re.sub(r'[\r\n]', ' ', msg)[:140], len(pay), len(rows), len(zones)), flush=True)
    return h, st, msg, pay, rows, zones

def main():
    print(MARK, flush=True)
    t0 = time.time()
    h, st, msg, pay = call('/orchestrator.OrchestrationService/Health', b'', t=25)
    print('HEALTH http=%s st=%s msg=%r len=%d' % (h, st, msg[:100], len(pay)), flush=True)
    if st != 0:
        print('HOST_NETFAIL health_not_ok', flush=True)
        return
    # one wildcard call: full fleet + every zone
    h, st, msg, pay, rows, zones = do_lh('', 150)
    got = rows if (st == 0 and len(rows) > 0) else []
    if not got:
        # fallback: source-derived production zone ids (active/provisioning/build),
        # at most 18, one call each, >=3s apart, short timeout.
        cand = ['eqsv2a','dpsjc','cssv9a','eqsv1a','aws-us-west-1a','aws-us-west-1c',
                'eqdc4a','eqdc16a','dpiad','aws-us-east-1a','aws-us-east-1b','aws-us-east-1c',
                'drams3a','drams11a','dpams','eqsg3a','drsin10a','dpsgp']
        for z in cand[:18]:
            if time.time() - t0 > 200: print('TIME_BUDGET_STOP', flush=True); break
            h2, st2, m2, p2, r2, zo2 = do_lh(z, 35)
            if st2 == 0 and r2:
                got = r2; rows = r2; zones = zo2
                print('FALLBACK_HIT zone=%s' % z, flush=True)
                break
            time.sleep(3)
    # summarize zones
    for zd, contrib in zones:
        print('ZR|%s|observed=%s|state=%s|count=%s|thr=%s|auto=%s|manual=%s|contrib=%s' % (
            zd.get(1, ''), zd.get(2), zd.get(3, ''), zd.get(9), zd.get(5), zd.get(7), zd.get(8),
            ','.join(contrib)[:200]), flush=True)
    # stacker rows -> compact records, no data_json values (keys/counts only)
    recs = []
    for d, pending in rows:
        dj = d.get(15) or ''
        keys = ''; dsum = ''
        if dj:
            try:
                o = json.loads(dj)
                keys = ','.join(sorted(o.keys()))[:200]
                parts = []
                for k in ('in_flight', 'failed', 'pending', 'placements_at_drain_start'):
                    if k in o:
                        vv = o[k]
                        parts.append('%s=%s' % (k, len(vv) if isinstance(vv, (list, dict)) else vv))
                dsum = ';'.join(parts)[:160]
            except Exception:
                keys = 'unparsable'
                dsum = 'len=%d' % len(dj)
        rec = {
            'id': d.get(1, ''), 'host': d.get(2, ''), 'zone': d.get(3, ''),
            'obs': d.get(4, 0), 'state': d.get(5, ''), 'reason': (d.get(6, '') or '')[:120],
            'rest': d.get(7, 0), 'deadline': d.get(8, ''), 'pending': pending[:6],
            'trig': d.get(10, ''), 'at': d.get(11, ''), 'status': d.get(12, 0),
            'cord': d.get(13, 0), 'cord_reason': (d.get(14, '') or '')[:80],
            'dj_keys': keys, 'dj_sum': dsum,
        }
        recs.append(rec)
    recs_sorted = sorted(recs, key=lambda r: (r['zone'], r['host'], r['id']))
    print('ROWS_TOTAL %d' % len(recs_sorted), flush=True)
    zonecount = {}
    for r in recs_sorted:
        z = r['zone'] or '<none>'
        zonecount[z] = zonecount.get(z, 0) + 1
    print('ZONECOUNTS ' + ';'.join('%s=%d' % (k, zonecount[k]) for k in sorted(zonecount)), flush=True)
    zchunks('FLEET', recs_sorted)
    # sample rows verbatim (compact)
    for i, r in enumerate(recs_sorted[:12]):
        print('SAMPLE%d %s' % (i, json.dumps(r, ensure_ascii=False)[:600]), flush=True)
    # GetDrainStatus on up to 5 real ids (each exactly once)
    ids = []
    for r in recs_sorted:
        if r['id'] and r['id'] not in ids:
            ids.append(r['id'])
        if len(ids) >= 5: break
    for sid in ids:
        h, st, msg, pay = call('/orchestrator.OrchestrationService/GetDrainStatus', fb(1, sid.encode()), t=30)
        info = {}; cnt = {2: 0, 4: 0, 8: 0, 9: 0, 11: 0}
        kinds = {}; states = {}
        try:
            for f, w, x in parse(pay):
                if w == 2 and f in (2, 4, 8, 9, 11):
                    cnt[f] += 1
                    d = parse_placement(x) if f != 11 else {}
                    if f != 11:
                        kinds[d.get(2, '')] = kinds.get(d.get(2, ''), 0) + 1
                        states[d.get(4, '')] = states.get(d.get(4, ''), 0) + 1
                elif w == 2: info[f] = dec(x)
                elif w == 0: info[f] = x
        except Exception as e:
            print('GDS %s PARSE_ERR %r' % (h16(sid), e), flush=True)
        print('GDS id=%s st=%s http=%s msg=%s state=%r observed=%s drain_started=%r inflight=%d unmanaged=%d waiting=%d moving=%d moved=%s failed=%d kinds=%s states=%s' % (
            sid, st, h, msg[:60], info.get(1), info.get(3), info.get(5), cnt[2], cnt[4], cnt[8], cnt[9],
            info.get(10), cnt[11], kinds, states), flush=True)
        time.sleep(1)
    # GetStackletConfig semantics on up to 3 ids (stub is expected empty)
    for sid in ids[:3]:
        h, st, msg, pay = call('/orchestrator.OrchestrationService/GetStackletConfig', fb(1, sid.encode()) + fb(2, 'sfo'), t=30)
        print('GSC sid=%s st=%s http=%s msg=%s paylen=%d hexhead=%s' % (sid, st, h, msg[:60], len(pay), pay[:24].hex()), flush=True)
        time.sleep(1)
    print('DONE elapsed=%ds calls=%d' % (int(time.time() - t0), CTR[0]), flush=True)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('FATAL %r' % e, flush=True)
