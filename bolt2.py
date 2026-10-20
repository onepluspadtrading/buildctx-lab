import struct, sys, json, re
PATH = sys.argv[1] if len(sys.argv) > 1 else '/f/meta.db'
MAXK = int(sys.argv[2]) if len(sys.argv) > 2 else 400
data = open(PATH, 'rb').read()
print("FILE size=%d" % len(data))
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]
pagesize=4096; meta_off=None
for cand in (0,1,2):
    off=cand*4096
    if off+80>len(data): break
    if u32(data,off+16)==0xED0CDAED:
        pagesize=u32(data,off+24); meta_off=off; break
if meta_off is None:
    print("NO_BOLT_MAGIC head=%s" % data[:64].hex()); sys.exit(0)
root=u64(data,meta_off+32); pgid=u64(data,meta_off+40); txid=u64(data,meta_off+48)
print("BOLT pagesize=%d root=%d pgid=%d txid=%d pages=%d" % (pagesize,root,pgid,txid,len(data)//pagesize))
def pinfo(p):
    off=p*pagesize
    if off+16>len(data): return None
    return off,u16(data,off+8),u16(data,off+10)
def items(p,depth=0,seen=None):
    if seen is None: seen=set()
    if p in seen or depth>30: return
    seen.add(p)
    i=pinfo(p)
    if not i: return
    off,flags,count=i
    if flags&0x02:
        for n in range(count):
            e=off+16+n*16
            if e+16>len(data): break
            ef=u32(data,e); pos=u32(data,e+4); ks=u32(data,e+8); vs=u32(data,e+12)
            k=data[e+pos:e+pos+ks]; v=data[e+pos+ks:e+pos+ks+vs]
            yield ef,k,v
        return
    for n in range(count):
        e=off+16+n*16
        if e+16>len(data): break
        pos=u32(data,e+4); child=u64(data,e+8)
        for x in items(child,depth+1,seen): yield x
def dec(b): return b.decode('utf-8','replace')
def strs(b,minlen=6,maxn=6):
    out=[]
    for m in re.finditer(rb'[ -~]{%d,}'%minlen,b):
        out.append(m.group().decode('latin-1'))
        if len(out)>=maxn: break
    return out
PAT=re.compile(r'railway|stacker|orchestrator|backboard|network-cp|railyard|railpack|pkg\.dev|gcr\.io|ghcr\.io|buildkit|railpack|station|csc',re.I)
# recursive bucket discovery
def buckets_of(p,depth=0,path=''):
    for ef,k,v in items(p):
        if (ef&0x01) and len(v)>=16:
            bk=u64(v,0); seq=u64(v,8); nm=dec(k)
            yield (path+'/'+nm if path else nm), bk, seq
tot=0
lvl1=list(buckets_of(root))
print("L1_BUCKETS: "+", ".join("%s(%d)"%(n,s) for n,_,s in lvl1))
for n1,b1,s1 in lvl1:
    sub=list(buckets_of(b1))
    if sub:
        print("L2_UNDER %s: "%n1 + ", ".join("%s(%d)"%(n,s) for n,_,s in sub))
    # leaf items directly in this bucket
    leaf=[(ef,k,v) for ef,k,v in items(b1) if not ((ef&0x01) and len(v)>=16)]
    print("BUCKET %s leafitems=%d" % (n1,len(leaf)))
    low=n1.lower()
    if 'images' in low:
        print("== IMAGES %s n=%d" % (n1,len(leaf)))
        plat=[]
        for i,(ef,k,v) in enumerate(leaf):
            nm=dec(k); ss=strs(v,6,4)
            if i<MAXK: print("IMG %s | %s" % (nm,' ; '.join(s[:100] for s in ss)))
            if PAT.search(nm) or PAT.search(' '.join(ss)): plat.append((nm,ss))
        print("IMAGES_PLATFORM_LIKE n=%d" % len(plat))
        for nm,ss in plat[:80]: print("IMGP %s | %s" % (nm,' ; '.join(s[:120] for s in ss)))
    elif low.endswith('/content') or 'content' in low:
        print("== CONTENT %s n=%d" % (n1,len(leaf)))
        from collections import Counter
        c=Counter(); pn=[]
        for ef,k,v in leaf:
            nm=dec(k); c[nm.split('/')[0]]+=1
            ss=strs(v,6,3)
            if PAT.search(nm) or PAT.search(' '.join(ss)): pn.append((nm,ss))
        print("CONTENT_NS", dict(c.most_common(10)))
        for nm,ss in pn[:60]: print("CONP %s | %s" % (nm,' ; '.join(s[:100] for s in ss)))
    elif low.endswith('/containers') or low.endswith('/snapshots') or 'lease' in low:
        print("== %s n=%d" % (n1,len(leaf)))
        for ef,k,v in leaf[:60]: print("IT %s | %s" % (dec(k),' ; '.join(s[:90] for s in strs(v,6,4))))
    for n2,b2,s2 in sub:
        leaf2=[(ef,k,v) for ef,k,v in items(b2) if not ((ef&0x01) and len(v)>=16)]
        print("BUCKET2 %s/%s leafitems=%d" % (n1,n2,len(leaf2)))
        low=(n1+'/'+n2).lower()
        if 'images' in low:
            plat=[]
            for i,(ef,k,v) in enumerate(leaf2):
                nm=dec(k); ss=strs(v,6,4)
                if i<MAXK: print("IMG %s | %s" % (nm,' ; '.join(s[:100] for s in ss)))
                if PAT.search(nm) or PAT.search(' '.join(ss)): plat.append((nm,ss))
            print("IMAGES2_PLATFORM_LIKE n=%d" % len(plat))
            for nm,ss in plat[:80]: print("IMGP2 %s | %s" % (nm,' ; '.join(s[:120] for s in ss)))
# global scan
toks={}
for m in re.finditer(rb'[ -~]{10,400}', data):
    s=m.group().decode('latin-1')
    if PAT.search(s): toks[s]=toks.get(s,0)+1
print("GLOBAL_PLAT uniq=%d" % len(toks))
for s in list(toks)[:120]: print("GS %s" % s[:200])
