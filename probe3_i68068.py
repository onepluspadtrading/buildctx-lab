#!/usr/bin/env python3
# I68068 phase3: (A) enumerate every dynamic-config key from source and read its value (read-only)
#                 (B) OrchestrationService method matrix using MALFORMED protobuf (handler never runs -> zero side effect)
#                 (C) read-only methods with nonexistent ids.  No write method is executed with a valid body.
import subprocess,struct,os,time,re,json
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
            l,i=rd(b,i)
            if i+l>len(b):raise ValueError('len')
            o.append((f,2,b[i:i+l]));i+=l
        elif w==5:o.append((f,5,b[i:i+4]));i+=4
        elif w==1:o.append((f,1,b[i:i+8]));i+=8
        else:raise ValueError('wt')
    return o
def s1(b,f,d=''):
    try:
        for k,w,x in parse(b):
            if k==f and w==2:return x.decode('utf-8','replace')
    except Exception:pass
    return d
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

SEC=re.compile(r'(?i)((?:token|secret|password|passwd|key|credential|dsn|bearer)[^,}\s]{0,3}[:=]\s*"?)([A-Za-z0-9_\-\.=+/:%]{12,})')
def red(s):
    return SEC.sub(lambda m: m.group(1)+'<REDACTED:%d>'%len(m.group(2)), s)

KEYS=['admission_control', 'assignment_leak_sampler', 'balise_cost', 'balise_operator_controls', 'build_vm', 'builder_compute_abuse', 'cooldown', 'cryptominer_detection', 'cve_watch', 'deployment_vm', 'devnew_ssh', 'ephemeral_port_limit', 'factory_vm', 'ha_static_egress', 'packstore_images', 'pre_pulled_images', 'registry_selection', 'scheduling_params', 'stacker_cpu_cap', 'stacker_failover', 'stacker_status', 'stacker_vm_runtime', 'stateless_preference', 'vm_reconcile', 'volume_label_reconcile', 'zfs_storage_resize_autopilot']
print('MARK I68068-p3 A: dynamic config keys=%d'%len(KEYS),flush=True)
BIG={'pre_pulled_images','registry_selection','packstore_images','zfs_storage_resize_autopilot','devnew_ssh','admission_control','factory_vm','build_vm','stacker_vm_runtime'}
for k in KEYS:
    h,st,m,pay=call('/orchestrator.DynamicConfigService/GetConfig',fb(1,k.encode()),t=20)
    ent=b''
    try:
        for f,w,x in parse(pay):
            if f==1 and w==2: ent=x
    except Exception: pass
    cj=s1(ent,3); name=s1(ent,7); ub=s1(ent,5); desc=s1(ent,4)
    lim=1400 if k in BIG else 500
    print('CFG %-32s http=%s st=%-2s len=%-6d name=%r desc=%r upto=%r json=%s' % (k,h,st,len(pay),name[:60],desc[:90],ub[:40],red(cj[:lim])),flush=True)
    time.sleep(0.6)

print('MARK I68068-p3 B: method matrix (malformed protobuf => handler never executes)',flush=True)
MAL=b'\x0a\xff\xff\xff\x0f'
METHODS="""StreamBuilderHeartbeats
Health
UpdateStacklet
StackletHeartbeat
GetStackletConfig
StackerHeartbeat
ReportStackerStatus
CheckVMAllocation
GetDrainStatus
DrainStacker
ReinstateStacker
CancelDrain
AcknowledgeLoss
ResetZoneBreaker
ListStackerHealth""".split()
for m in METHODS:
    h,st,msg,pay=call('/orchestrator.OrchestrationService/'+m,MAL,t=12)
    print('M %-24s http=%s st=%-4s msg=%r' % (m,h,st,msg[:110]),flush=True)
    time.sleep(0.5)
h,st,msg,pay=call('/orchestrator.OrchestrationService/NoSuchMethodNothing',MAL,t=12)
print('M %-24s http=%s st=%-4s msg=%r' % ('<unknown-method>',h,st,msg[:110]),flush=True)

print('MARK I68068-p3 C: read-only with nonexistent ids',flush=True)
NID=b'i68068-nonexistent'
for tag,p,body in [('Health','/orchestrator.OrchestrationService/Health',b''),
                   ('GetStackletConfig','/orchestrator.OrchestrationService/GetStackletConfig',fb(1,NID)+fb(2,b'zz-i68068')),
                   ('GetDrainStatus','/orchestrator.OrchestrationService/GetDrainStatus',fb(1,NID)),
                   ('CheckVMAllocation','/orchestrator.OrchestrationService/CheckVMAllocation',fb(1,NID)),
                   ('ListStackerHealth(zone=zz-i68068)','/orchestrator.OrchestrationService/ListStackerHealth',fb(1,b'zz-i68068'))]:
    h,st,msg,pay=call(p,body,t=25)
    print('R %-30s http=%s st=%-4s msg=%r len=%d hex=%s' % (tag,h,st,msg[:100],len(pay),pay[:80].hex()),flush=True)
    time.sleep(0.8)
print('MARK I68068-p3 DONE',flush=True)
