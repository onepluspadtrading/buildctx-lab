#!/usr/bin/env python3
# I68068: source-derived route-table validation against external-mtls-service-gateway-us-west1:443
# Read-only by design: only Health / Get / List methods are invoked. No write method is called.
import subprocess, struct, sys, os, time, re
G = 'https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA='/pki/server-ca-bundle.crt'; CRT='/pki/client.crt'; KEY='/pki/client.key'
CTR=[0]; MARK=os.environ.get('MARK','I68068')

def varint(n):
    o=bytearray()
    while True:
        b=n&0x7f; n>>=7
        if n: o.append(b|0x80)
        else:
            o.append(b); return bytes(o)
def fb(f,b): return varint((f<<3)|2)+varint(len(b))+b
def fs(f,s): return fb(f, s.encode() if isinstance(s,str) else s)
def rd_varint(b,i):
    r=0;s=0
    while i<len(b):
        x=b[i]; r|=(x&0x7f)<<s; i+=1
        if not x&0x80: return r,i
        s+=7
        if s>63: break
    raise ValueError('varint')
def parse(b):
    i=0;out=[]
    while i<len(b):
        k,i=rd_varint(b,i); f=k>>3; w=k&7
        if f==0: raise ValueError('f0')
        if w==0:
            v,i=rd_varint(b,i); out.append((f,0,v))
        elif w==2:
            l,i=rd_varint(b,i)
            if i+l>len(b): raise ValueError('len')
            out.append((f,2,b[i:i+l])); i+=l
        elif w==5: out.append((f,5,b[i:i+4])); i+=4
        elif w==1: out.append((f,1,b[i:i+8])); i+=8
        else: raise ValueError('wt')
    return out
def allof(b,f):
    try: return [v for k,w,v in parse(b) if k==f and w==2]
    except Exception: return []

def call(path, body=b'', timeout=20):
    CTR[0]+=1; n=CTR[0]
    fu='/tmp/r%d.bin'%n; hu='/tmp/h%d.txt'%n; bu='/tmp/b%d.bin'%n; tu='/tmp/t%d.txt'%n
    open(fu,'wb').write(b'\x00'+struct.pack('>I',len(body))+body)
    a=['curl','-sS','--http2','--connect-timeout','5','-m',str(timeout),'-D',hu,'-o',bu,'--trace-ascii',tu,'-w','%{http_code}',
       '--cert',CRT,'--key',KEY,'--cacert',CA,'-X','POST',G+path,'-H','te: trailers',
       '-H','content-type: application/grpc','--data-binary','@'+fu]
    p=subprocess.run(a,capture_output=True,text=True)
    code=p.stdout.strip(); hdr=open(hu,'rb').read().decode('utf-8','replace') if os.path.exists(hu) else ''
    data=open(bu,'rb').read() if os.path.exists(bu) else b''
    tr=open(tu,'rb').read().decode('utf-8','replace') if os.path.exists(tu) else ''
    st=re.findall(r'grpc-status:\s*(\d+)',tr,re.I) or re.findall(r'grpc-status:\s*(\d+)',hdr,re.I)
    msg=re.findall(r'grpc-message:\s*([^\r\n]*)',tr,re.I) or re.findall(r'grpc-message:\s*([^\r\n]*)',hdr,re.I)
    st=int(st[-1]) if st else None
    m=msg[-1].strip() if msg else ''
    # strip 5-byte gRPC frame from response body
    payload=b''
    if len(data)>=5 and data[0]==0:
        ln=struct.unpack('>I',data[1:5])[0]
        payload=data[5:5+ln]
    err=(p.stderr or '').strip()[:120]
    return dict(path=path,http=code,status=st,msg=m,payload=payload,err=err,raw=data)

def show(r, maxhex=160, label=''):
    print('%s %-70s http=%s grpc=%s msg=%r len=%d err=%r' % (label,r['path'],r['http'],r['status'],r['msg'][:150],len(r['payload']),r['err']))
    if r['payload']:
        print('    hex:',r['payload'][:maxhex].hex())
        try:
            print('    txt:',r['payload'][:300].decode('utf-8','replace').replace('\n',' '))
        except Exception: pass

def strf(b,f):
    v=allof(b,f)
    return v[0].decode('utf-8','replace') if v else ''

def main():
    print('MARK',MARK,'start',time.strftime('%H:%M:%S'))
    print('== POSITIVE CONTROL: grpc health + temporal GetSystemInfo')
    r=call('/grpc.health.v1.Health/Check',b''); show(r,40,'[ctl]')
    r=call('/temporal.api.workflowservice.v1.WorkflowService/GetSystemInfo',b''); show(r,80,'[ctl]')
    time.sleep(1)
    print('== ROUTED-BY-SOURCE: orchestrator.OrchestrationService')
    r=call('/orchestrator.OrchestrationService/Health',b''); show(r,40,'[orch]')
    time.sleep(1)
    r=call('/orchestrator.OrchestrationService/ListStackerHealth',b'')  # ListStackerHealthRequest{zone:""} = all zones
    show(r,400,'[orch]')
    rows=[]; zones=[]
    for i,row in enumerate(allof(r['payload'],1)):
        try:
            rows.append((strf(row,1),strf(row,2),strf(row,3),strf(row,5),strf(row,6),strf(row,14)))
        except Exception as e: rows.append(('ERR',repr(e)))
    for row in allof(r['payload'],2):
        try: zones.append((strf(row,1),strf(row,3),strf(row,7),strf(row,9)))
        except Exception: pass
    print('    STACKER_ROWS',len(rows))
    for x in rows[:10]: print('     ',x)
    print('    ZONE_ROWS',len(zones))
    for x in zones[:10]: print('     ',x)
    time.sleep(1)
    sid = rows[0][0] if rows else 'nonexistent-i68068'
    body=fb(1, sid.encode())
    r=call('/orchestrator.OrchestrationService/GetDrainStatus',body); show(r,300,'[orch]')  # read-only
    time.sleep(1)
    body=fb(1,b'nonexistent-i68068')+fb(2,b'us-west1')
    r=call('/orchestrator.OrchestrationService/GetStackletConfig',body); show(r,300,'[orch]')
    time.sleep(1)
    body=fb(1,b'nonexistent-i68068')
    r=call('/orchestrator.OrchestrationService/CheckVMAllocation',body); show(r,200,'[orch]')  # best-effort read, no vm ids
    time.sleep(1)
    print('== ROUTED-BY-SOURCE: DynamicConfigService/GetConfig (exact path)')
    for key in ('stacker_status','cryptominer_detection'):
        body=fb(1,key.encode())
        r=call('/orchestrator.DynamicConfigService/GetConfig',body); show(r,400,'[dyn]')
        try:
            ent=allof(r['payload'],1)[0]
            print('    key=%s name=%s updated_by=%s config_json[:300]=%s' % (strf(ent,1),strf(ent,7),strf(ent,6),strf(ent,3)[:300]))
        except Exception as e: print('    decode_err',repr(e))
        time.sleep(1)
    print('== NEGATIVE CONTROLS (must NOT be routed)')
    for p,b in [('/orchestrator.DynamicConfigService/ListConfigs',b''),
                ('/orchestrator.DynamicConfigService/PullConfigs',b''),
                ('/orchestrator.StackersService/ListStackers',b''),
                ('/orchestrator.OrchestrationService/NoSuchMethodNothing',b''),
                ('/nonexistent.Service/Method',b'')]:
        r=call(p,b); show(r,80,'[neg]'); time.sleep(1)
    print('MARK',MARK,'done',time.strftime('%H:%M:%S'))

if __name__=='__main__':
    main()
