import re,collections
P='/mnt/data/vm_constructor_full.il.txt'
s=open(P,encoding='utf-16').read()
ins=[]
for m in re.finditer(r'IL_([0-9A-F]{4}):[ \t]+([\w.]+)(?:[ \t]+([^\r\n]*))?',s):
    ins.append((int(m[1],16),m[2],(m[3] or '').strip()))
idx={a:i for i,(a,_,_) in enumerate(ins)}
U=0xffffffff
stack=[]; local=0; fields={}; registrations=[]; seen=collections.Counter(); pc=0
class Obj:
    def __init__(self,typ,data=None):self.typ,self.data=typ,data
    def __repr__(self):return f'{self.typ}({self.data})'
THIS=Obj('this')
def word(v):return v&U
def pop():return stack.pop()
def asint(v):
    if not isinstance(v,int):raise ValueError(f'expected int got {v}')
    return v&U
for steps in range(100000):
    if pc not in idx:raise RuntimeError(f'bad pc {pc:x}')
    seen[pc]+=1
    if seen[pc]>10:raise RuntimeError(f'loop at {pc:x}, regs {len(registrations)}')
    i=idx[pc]; addr,op,arg=ins[i];
    nxt=ins[i+1][0] if i+1<len(ins) else None
    if op=='ldarg.0':stack.append(THIS)
    elif op=='ldloc.0':stack.append(local)
    elif op=='stloc.0':local=asint(pop())
    elif op=='ldc.i4':stack.append(word(int(arg.split()[0])))
    elif op in ('add','sub','mul','xor','and','or','shl','shr.un','div.un','rem.un'):
        b=asint(pop());a=asint(pop())
        if op=='add':v=a+b
        elif op=='sub':v=a-b
        elif op=='mul':v=a*b
        elif op=='xor':v=a^b
        elif op=='and':v=a&b
        elif op=='or':v=a|b
        elif op=='shl':v=a<<(b&31)
        elif op=='shr.un':v=a>>(b&31)
        elif op=='div.un':v=a//b
        elif op=='rem.un':v=a%b
        stack.append(word(v))
    elif op=='newobj':
        if 'Dictionary`2' in arg:stack.append(Obj('dictionary',{}))
        elif 'List`1' in arg:stack.append(Obj('list'))
        elif "'95969DA2'::.ctor" in arg:
            meth=pop();target=pop();stack.append(Obj('delegate',meth))
        else:stack.append(Obj('object',arg))
    elif op=='stfld':
        val=pop();target=pop();assert target is THIS,(addr,target); field=arg.split('::')[-1];fields[field]=val
    elif op=='ldfld':
        target=pop();assert target is THIS,(addr,target);field=arg.split('::')[-1];stack.append(fields[field])
    elif op=='ldftn':
        stack.append(arg.split('::')[-1])
    elif op=='call':
        if 'System.Object::.ctor' in arg:
            ob=pop();assert ob is THIS
        else:raise Exception(('unexpected call',addr,arg))
    elif op=='callvirt':
        if '::set_Item' in arg:
            val=pop(); keyobj=pop();
            if not isinstance(keyobj,int):print('FAIL',hex(addr),'key',keyobj,'val',val,'remaining',stack[-8:]);
            key=asint(keyobj);ob=pop();assert ob.typ=='dictionary',(addr,ob)
            ob.data[key]=val
            registrations.append((addr,key,val.data))
        elif 'System.Object::.ctor' in arg:
            ob=pop();assert ob is THIS
        else:raise Exception(('unknown callvirt',hex(addr),arg))
    elif op in ('brfalse','brtrue'):
        a=asint(pop());cond=(a==0) if op=='brfalse' else (a!=0)
        if cond:nxt=int(re.search(r'IL_([0-9A-F]{4})',arg)[1],16)
    elif op in ('bgt.un','blt.un','bge.un','ble.un','beq'):
        b=asint(pop());a=asint(pop())
        cond={'bgt.un':a>b,'blt.un':a<b,'bge.un':a>=b,'ble.un':a<=b,'beq':a==b}[op]
        if cond:nxt=int(re.search(r'IL_([0-9A-F]{4})',arg)[1],16)
    elif op=='ret':break
    else:raise Exception(('unknown',addr,op,arg))
    pc=nxt
else:raise RuntimeError('step bound')
print('executed',steps+1,'instructions; registrations',len(registrations),'distinct',len(fields['F49E028B'].data),'method refs',len(set(x[2] for x in registrations)))
for a,k,v in registrations[:20]:print(f'0x{k:02X} {v:<20} IL_{a:04X}')
print('validated:', [(k,fields['F49E028B'].data.get(k)) for k in (0,1,2)])
with open('/mnt/data/vm_opcode_map.csv','w') as f:
 f.write('opcode_hex,opcode_decimal,handler,register_il_offset\n')
 for a,k,v in sorted(registrations,key=lambda x:x[1]):f.write(f'0x{k:02X},{k},{v},IL_{a:04X}\n')
