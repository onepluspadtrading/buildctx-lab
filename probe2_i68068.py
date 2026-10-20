#!/usr/bin/env python3
# I68068 phase2: compact classification of routed vs non-routed paths + fleet view retry. Read-only.
import subprocess,struct,os,time,re,sys
G='https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA='/pki/server-ca-bundle.crt';CRT='/pki/client.crt';KEY='/pki/client.key'
CTR=[0]
def v(n):
    o=bytearray()
    while True:
        b=n&0x7f;n>>=7
        if n:o.append(b|0x80)
        else:o.append(b);return bytes(o)
def fb(f,b):return v((f<<3)|2)+v(len(b))+b
def rd(b,i):
    r=0;s=0
    while i<len(b):
        x=b[i];r|=(x&0x7f)<<s;i+=1
        if not x&0x80:return r,i
        s+=7
    raise ValueError
def parse(b):
    i=0;o=[]
    while i<len(b):
        k,i=rd(b,i);f=k>>3;w=k&7
        if w==0:
            x,i=rd(b,i);o.append((f,0,x))
        elif w==2:
            l,i=rd(b,i);o.append((f,2,b[i:i+l]));i+=l
        elif w==5:o.append((f,5,b[i:i+4]));i+=4
        elif w==1:o.append((f,1,b[i:i+8]));i+=8
        else:raise ValueError
    return o
def s1(b,f,default=''):
    try:
        for k,w,x in parse(b):
            if k==f and w==2:return x.decode('utf-8','replace')
    except Exception:pass
    return default
def call(p,body=b'',t=20):
    CTR[0]+=1;n=CTR[0]
    fu='/tmp/r%d'%n;hu='/tmp/h%d'%n;bu='/tmp/b%d'%n;tu='/tmp/t%d'%n
    open(fu,'wb').write(b'\x00'+struct.pack('>I',len(body))+body)
    a=['curl','-sS','--http2','--connect-timeout','5','-m',str(t),'-D',hu,'-o',bu,'--trace-ascii',tu,'-w','%{http_code}',
       '--cert',CRT,'--key',KEY,'--cacert',CA,'-X','POST',G+p,'-H','te: trailers','-H','content-type: application/grpc','--data-binary','@'+fu]
    q=subprocess.run(a,capture_output=True,text=True)
    data=open(bu,'rb').read() if os.path.exists(bu) else b''
    tr=open(tu,'rb').read().decode('utf-8','replace') if os.path.exists(tu) else ''
    hd=open(hu,'rb').read().decode('utf-8','replace') if os.path.exists(hu) else ''
    st=re.findall(r'grpc-status:\s*(\d+)',tr,re.I) or re.findall(r'grpc-status:\s*(\d+)',hd,re.I)
    msg=re.findall(r'grpc-message:\s*([^\r\n]*)',tr,re.I) or re.findall(r'grpc-message:\s*([^\r\n]*)',hd,re.I)
    pay=b''
    if len(data)>=5 and data[0]==0:
        l=struct.unpack('>I',data[1:5])[0];pay=data[5:5+l]
    return q.stdout.strip(),(int(st[-1]) if st else None),(msg[-1].strip() if msg else ''),pay
def one(tag,p,body=b'',t=20):
    h,st,m,pay=call(p,body,t)
    print('%-46s http=%-3s grpc=%-4s msg=%r len=%d' % (tag,h,st,m[:90],len(pay)),flush=True)
    return st,pay
print('MARK I68068-gwroute-p2 start',flush=True)
one('C1 Health','/grpc.health.v1.Health/Check')
one('C2 OrchestrationService/Health','/orchestrator.OrchestrationService/Health')
one('C3 DynCfg/GetConfig(stacker_status)','/orchestrator.DynamicConfigService/GetConfig',fb(1,b'stacker_status'))
time.sleep(1)
print('-- fleet view (read-only, retries)',flush=True)
for z in (b'',b'us-west1',b'gcp-us-west1'):
    st,pay=one('R ListStackerHealth zone=%r'%z.decode(),'/orchestrator.OrchestrationService/ListStackerHealth',fb(1,z) if z else b'',t=25)
    n=0
    try:
        for k,w,x in parse(pay):
            if k==1 and w==2:
                n+=1
                if n<=6: print('   stacker:',s1(x,1),s1(x,2),s1(x,3),s1(x,5),s1(x,6)[:60],flush=True)
    except Exception as e: print('   parse_err',repr(e),flush=True)
    print('   rows',n,flush=True)
    time.sleep(2)
print('-- negative controls',flush=True)
for tag,p in [('N1 non-routed DynamicConfigService/ListConfigs','/orchestrator.DynamicConfigService/ListConfigs'),
              ('N2 non-routed StackersService/ListStackers','/orchestrator.StackersService/ListStackers'),
              ('N3 non-routed unknown service','/nonexistent.Service/Method'),
              ('N4 routed-prefix unknown method','/orchestrator.OrchestrationService/NoSuchMethodNothing')]:
    one(tag,p)
    time.sleep(1)
print('MARK I68068-gwroute-p2 done',flush=True)
