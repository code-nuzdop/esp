import struct
b=open('/mnt/data/SjTNlCHNfW(1).exe','rb').read()
u16=lambda p:struct.unpack_from('<H',b,p)[0];u32=lambda p:struct.unpack_from('<I',b,p)[0];u64=lambda p:struct.unpack_from('<Q',b,p)[0]
pe=u32(0x3c);opt=pe+24;clr=u32(opt+96+14*8);clrfo=0x600+(clr-0x7f8000);metadata_rva=u32(clrfo+8);meta=0x600+(metadata_rva-0x7f8000)
assert b[meta:meta+4]==b'BSJB';versionlen=u32(meta+12);p=(meta+16+versionlen+3)&~3;flags,streams=u16(p),u16(p+2);p+=4
print('metadata',hex(meta),'version',b[meta+16:meta+16+versionlen]);streamoffs={}
for _ in range(streams):
 off=u32(p);size=u32(p+4);p+=8;end=b.index(0,p);name=b[p:end].decode();p=(end+4)&~3
 streamoffs[name]=(meta+off,size)
print('streams',streamoffs)
tbl=streamoffs['#~'][0];print('tables',hex(tbl));heap_flags=b[tbl+6];valid=u64(tbl+8);p=tbl+24;rows={}
for i in range(64):
 if valid&(1<<i):rows[i]=u32(p);p+=4
print('rowcounts subset',[(i,rows[i]) for i in rows if i<10]);print('heap_flags',bin(heap_flags),'start',hex(p))
stringwidth=4 if heap_flags&1 else 2;guidwidth=4 if heap_flags&2 else 2
modsize=2+stringwidth+guidwidth*3
p+=modsize*rows.get(0,0)
typerefs=rows.get(1,0)
scoperows=max(rows.get(i,0) for i in (0,1,26,35));scopewidth=2 if scoperows < (1<<14) else 4
readn=lambda pos,width:u16(pos) if width==2 else u32(pos)
def getstr(index):
 base=streamoffs['#Strings'][0];end=b.index(0,base+index);return b[base+index:end].decode('utf-8','replace')
for k in [1,2,84,85,254]:
 if not 1<=k<=typerefs:continue
 q=p+(k-1)*(scopewidth+2*stringwidth)
 scope=readn(q,scopewidth);nameidx=readn(q+scopewidth,stringwidth);nsidx=readn(q+scopewidth+stringwidth,stringwidth)
 print('TypeRef',k,hex(0x01000000+k),'scope',scope,'namespace',getstr(nsidx),'name',getstr(nameidx))
