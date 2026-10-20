import subprocess,struct,os,time,re
G='https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA='/pki/server-ca-bundle.crt';CRT='/pki/client.crt';KEY='/pki/client.key'
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
            if i+l>len(b):raise ValueError
            o.append((f,2,b[i:i+l]));i+=l
        elif w==5:o.append((f,5,b[i:i+4]));i+=4
        elif w==1:o.append((f,1,b[i:i+8]));i+=8
        else:raise ValueError
    return o
def s1(b,f,d=''):
    try:
        for k,w,x in parse(b):
            if k==f and w==2:return x.decode('utf-8','replace')
    except Exception:pass
    return d
n=[0]
def gc(key,t=20):
    n[0]+=1;j=n[0]
    body=fb(1,key.encode());fu='/tmp/f%d'%j;bu='/tmp/o%d'%j;tu='/tmp/t%d'%j;hu='/tmp/h%d'%j
    open(fu,'wb').write(b'\x00'+struct.pack('>I',len(body))+body)
    subprocess.run(['curl','-sS','--http2','--connect-timeout','5','-m',str(t),'-D',hu,'-o',bu,'--trace-ascii',tu,'-w','%{http_code}',
      '--cert',CRT,'--key',KEY,'--cacert',CA,'-X','POST',G+'/orchestrator.DynamicConfigService/GetConfig','-H','te: trailers',
      '-H','content-type: application/grpc','--data-binary','@'+fu],capture_output=True,text=True)
    data=open(bu,'rb').read() if os.path.exists(bu) else b''
    tr=open(tu,'rb').read().decode('utf-8','replace') if os.path.exists(tu) else ''
    st=re.findall(r'grpc-status:\s*(\d+)',tr,re.I)
    pay=b''
    if len(data)>=5 and data[0]==0:
        l=struct.unpack('>I',data[1:5])[0];pay=data[5:5+l]
    ent=b''
    try:
        for f,w,x in parse(pay):
            if f==1 and w==2: ent=x
    except Exception: pass
    return (int(st[-1]) if st else None), s1(ent,2), s1(ent,3), s1(ent,6), len(pay)
KEYS=['registry_selection','scheduling_params','packstore_images','factory_vm','deployment_vm','stateless_preference','builder_compute_abuse','admission_control','zfs_storage_resize_autopilot','cve_watch']
print('MARK I68068-p4 start',flush=True)
for k in KEYS:
    st,name,js,ub,ln=gc(k)
    print('CFG %-30s st=%-3s len=%-6d name=%r upto=%r' % (k,st,ln,name[:50],ub[:40]),flush=True)
    print('JSON '+js[:2300],flush=True)
    time.sleep(0.7)
print('MARK I68068-p4 done',flush=True)
