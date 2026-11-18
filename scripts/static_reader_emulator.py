"""Static emulation of three *specific* dnSpy IL methods. Does NOT load or execute the PE.
Reads snapshot bytes only and interprets a supported subset of IL opcodes.
"""
import re,struct,zipfile,collections
EXE='/mnt/data/SjTNlCHNfW(1).exe'
IL_ZIP='/mnt/data/Recovery-Step10.zip'
IL_INDEX='/mnt/data/SjTNlCHNfW_disassembly.il.txt'
z=zipfile.ZipFile(IL_ZIP)
data=open(EXE,'rb').read()
U=(1<<32)-1

# Resolve a virtual address against PE section headers, never loading the PE.
def mem_read(addr,size):
    rva=addr-0x400000
    peoff=struct.unpack_from('<I',data,0x3c)[0]
    nsects=struct.unpack_from('<H',data,peoff+6)[0]
    optsize=struct.unpack_from('<H',data,peoff+20)[0]
    opt=peoff+24
    sect=opt+optsize
    for i in range(nsects):
        p=sect+40*i
        vsize,va,rawsize,rawptr=struct.unpack_from('<IIII',data,p+8)
        if va<=rva and rva+size<=va+min(vsize,rawsize):
            at=rawptr+rva-va
            return int.from_bytes(data[at:at+size],'little')
    raise RuntimeError(f'virtual address {addr:#x} not backed by PE bytes')

def parse(token):
 try:txt=z.read(f'{token}.il.txt').decode('utf-8-sig')
 except KeyError:
  all_il=open(IL_INDEX).read()
  start=all_il.index('// '+token+' ')
  end=all_il.find('\n// 0x', start+5)
  txt=all_il[start:end if end>=0 else None]
 ins=[]
 for m in re.finditer(r'IL_([A-Fa-f0-9]{4}):[ \t]+([A-Za-z0-9_.]+)(?:[ \t]+([^\r\n]+))?',txt):
  ofs,op,arg=int(m[1],16),m[2],(m[3] or '').strip()
  ins.append((ofs,op,arg))
 return ins

class Reader:
 def __init__(self,pos):self.fields={'D38A0391':pos&U,'78A03A01':pos&U}
 def execute(self,token,verbose=False):
  ins=parse(token); idx={t[0]:i for i,t in enumerate(ins)}; s=[];loc={0:0,1:0};pc=0;visit=collections.Counter()
  for steps in range(10000):
   if pc not in idx: raise ValueError(f'pc {pc:x} not found')
   visit[pc]+=1
   if visit[pc]>15: raise RuntimeError(f'loop at {pc:x}')
   i=idx[pc];ofs,op,arg=ins[i];nxt=ins[i+1][0] if i+1<len(ins) else None
   if verbose:print(f'{ofs:04x} {op} {arg[:70]:70} local={loc} stack={s[-4:]}')
   a=lambda :s.pop()
   if op=='ldarg.0':s.append('this')
   elif op.startswith('ldloc.'):
    j=int(op[-1]);s.append(loc[j])
   elif op.startswith('stloc.'):
    j=int(op[-1]);loc[j]=a()&(255 if j==0 and token=='0x060000D3' else 65535 if j==1 and token=='0x060000D4' else 255 if j==1 and token=='0x060000DE' else U)
   elif op=='ldc.i4':s.append(int(arg.split()[0])&U)
   elif op in ('add','sub','mul','xor','and','or','shl','shr.un','div.un','rem.un'):
    y=a();x=a()
    if op=='add':v=x+y
    elif op=='sub':v=x-y
    elif op=='mul':v=x*y
    elif op=='xor':v=x^y
    elif op=='and':v=x&y
    elif op=='or':v=x|y
    elif op=='shl':v=x<<(y&31)
    elif op=='shr.un':v=x>>(y&31)
    elif op=='div.un':v=x//y
    elif op=='rem.un':v=x%y
    s.append(v&U)
   elif op=='ldfld':
    ob=a();assert ob=='this';s.append(self.fields[({'0x04000093':'D38A0391','0x04000094':'78A03A01'}.get(arg) or arg.split('::')[-1].strip(chr(39)))])
   elif op=='stfld':
    val=a();ob=a();assert ob=='this';self.fields[({'0x04000093':'D38A0391','0x04000094':'78A03A01'}.get(arg) or arg.split('::')[-1].strip(chr(39)))]=val&U
   elif op=='call':
    if '14B13C9A' in arg or '0x060002EB' in arg:
     offset=a();s.append(0x400000+offset) # for file-based assembly: direct RVA mapping
    elif 'op_Explicit' in arg or '0x0A00009D' in arg:pass # int pointer -> void* same value
    else:raise NotImplementedError((ofs,op,arg))
   elif op=='ldind.u1':s.append(mem_read(a(),1))
   elif op=='ldind.u4':s.append(mem_read(a(),4))
   elif op=='ldind.u2':s.append(mem_read(a(),2))
   elif op in ('conv.u1','conv.u2','conv.i4','conv.u4','conv.i2'):
    v=a(); s.append(v&{'conv.u1':255,'conv.u2':65535,'conv.i4':U,'conv.u4':U,'conv.i2':65535}[op])
   elif op in ('brfalse','brtrue','brfalse.s','brtrue.s'):
    x=a();cond=(x==0) if op.startswith('brfalse') else (x!=0)
    if cond:nxt=int(re.search(r'IL_([0-9A-Fa-f]+)',arg)[1],16)
   elif op in ('bgt.un','blt.un','bge.un','ble.un','beq','bne.un','bgt','blt','bge','ble'):
    y=a();x=a();
    if op.endswith('.un') or op in ['beq']:
     x&=U;y&=U
    else:
     if x>=1<<31:x-=1<<32
     if y>=1<<31:y-=1<<32
    cmp={'bgt.un':x>y,'blt.un':x<y,'bge.un':x>=y,'ble.un':x<=y,'beq':x==y,'bne.un':x!=y,'bgt':x>y,'blt':x<y,'bge':x>=y,'ble':x<=y}[op]
    if cmp:nxt=int(re.search(r'IL_([0-9A-Fa-f]+)',arg)[1],16)
   elif op in ('br','br.s'):nxt=int(re.search(r'IL_([0-9A-Fa-f]+)',arg)[1],16)
   elif op=='ret':
    val=a() if s else None
    if verbose:print('END:',steps,'value',val,'fields',self.fields)
    return val,steps
   elif op=='neg':s.append((-a())&U)
   elif op=='not':s.append((~a())&U)
   elif op=='nop':pass
   else:raise NotImplementedError((ofs,op,arg))
   pc=nxt
  raise RuntimeError('instruction bound exceeded')

if __name__=='__main__':
    import csv,hashlib
    print('SHA256:',hashlib.sha256(data).hexdigest())
    map_path='/mnt/data/vm_opcode_map.csv'
    opmap=list(csv.DictReader(open(map_path)))
    trace=[]
    r=Reader(0x7fa6e1)
    for number,token in enumerate(('0x060000D3','0x060000DB','0x060000D3','0x060000D3','0x060000DB','0x060000D3')):
        before=r.fields['D38A0391']
        value,steps=r.execute(token)
        note='opcode' if token.endswith('D3') else 'uint32 operand'
        handler=opmap[value]['handler'] if note=='opcode' else ''
        trace.append((f'{before:#x}',note,f'{value:#x}',handler,f'{r.fields["D38A0391"]:#x}'))
    print('Root stream preview (raw reader calls; later opcodes may use other operand lengths):')
    for x in trace:print(x)
    nested=Reader(0x80054a)
    print('Nested stream at 0x80054a:')
    for tok in ('0x060000D4','0x060000DB','0x060000DB','0x060000D3','0x060000DB','0x060000D3','0x060000D3'):
        before=nested.fields['D38A0391'];v,steps=nested.execute(tok)
        print(tok,hex(before),hex(v),hex(nested.fields['D38A0391']))
