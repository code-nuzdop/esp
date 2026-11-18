import sys,csv,json,hashlib,struct,collections,math,os
sys.path.insert(0,'/mnt/data')
from static_reader_emulator import Reader, mem_read, data
maps=list(csv.DictReader(open('/mnt/data/vm_opcode_map.csv')))
R=[]
def add(stream,step,cursor_before,operand_kind,val,handler,cursor_after,comment):
 R.append({'stream':stream,'step':step,'cursor_before_rva':f'0x{cursor_before:08X}', 'kind':operand_kind,'decoded_value':f'0x{val:X}', 'handler':handler,'cursor_after_rva':f'0x{cursor_after:08X}','interpretation':comment})
def take(stream,step,reader,method,kind,comment=''):
 a=reader.fields['D38A0391'];v,n=reader.execute(method)
 after=reader.fields['D38A0391'];handler=maps[v]['handler'] if kind=='opcode' else ''
 add(stream,step,a,kind,v,handler,after,comment)
 return v
root=Reader(0x7fa6e1)
assert take('outer',1,root,'0x060000D3','opcode','push 32-bit integer from following encoded operand')==0x10
assert take('outer',2,root,'0x060000DB','uint32 operand','0x10 pushes this value')==0
assert take('outer',3,root,'0x060000D3','opcode','0x50 pops top VM stack value')==0x50
assert take('outer',4,root,'0x060000D3','opcode','0x50 pops another VM stack value; initial dispatcher seeded an argument wrapper')==0x50
assert take('outer',5,root,'0x060000D3','opcode','0x10 pushes the following encoded uint32')==0x10
assert take('outer',6,root,'0x060000DB','uint32 operand','address or selector subsequently consumed by 0x53')==0x80054a
assert take('outer',7,root,'0x060000D3','opcode','0x53 invokes another VM interpreter with encoded operands')==0x53
child=Reader(0x80054a)
assert take('nested',1,child,'0x060000D4','uint16 header','zero argument count in 0x53 nested call')==0
assert take('nested',2,child,'0x060000DB','uint32 header','zero return-type identifier/marker; precise role depends on 0x53 branches')==0
assert take('nested',3,child,'0x060000DB','uint32 header','value 10; 0x53 consumes an additional 32-bit field')==10
assert take('nested',4,child,'0x060000D3','opcode','nested interpreter first opcode, push integer')==0x10
assert take('nested',5,child,'0x060000DB','uint32 operand','push integer 0')==0
assert take('nested',6,child,'0x060000D3','opcode','pop integer 0')==0x50
assert take('nested',7,child,'0x060000D3','opcode','E82B3785 operates on encoded data and runtime object; detailed semantics unresolved')==0x40
assert take('nested',8,child,'0x060000DE','uint8 operand','first 0x40 control byte; role unresolved')==0
assert take('nested',9,child,'0x060000DB','uint32 operand','first decoded 32-bit operand for 0x40')==0x3ea520
assert take('nested',10,child,'0x060000DB','uint32 operand','second decoded 32-bit operand for 0x40')==0x3ea532
assert take('nested',11,child,'0x060000DB','uint32 operand','third decoded 32-bit operand for 0x40')==0x7fef12
assert take('nested',12,child,'0x060000DB','uint32 operand','fourth decoded 32-bit operand for 0x40')==0x1000054
assert take('nested',13,child,'0x060000D3','opcode','0xCF also maps to E82B3785; another record follows')==0xCF
assert take('nested',14,child,'0x060000DE','uint8 operand','control byte for 0xCF record')==0
assert take('nested',15,child,'0x060000DB','uint32 operand','first 0xCF operand')==0x3eaf6c
assert take('nested',16,child,'0x060000DB','uint32 operand','second 0xCF operand')==0x3eaf8a
assert take('nested',17,child,'0x060000DB','uint32 operand','third 0xCF operand')==0x7fc0fe
assert take('nested',18,child,'0x060000DB','uint32 operand','fourth 0xCF operand')==0x1000054
assert take('nested',19,child,'0x060000D3','opcode','0x10 read/push 32-bit integer')==0x10
assert take('nested',20,child,'0x060000DB','uint32 operand','push 0x7C')==0x7c
assert take('nested',21,child,'0x060000D3','opcode','0x39 resolves an encoded FieldInfo')==0x39
assert take('nested',22,child,'0x060000DB','uint32 operand','field token 0x04000195 (VM evaluation stack field)')==0x04000195
assert take('nested',23,child,'0x060000D3','opcode','0x1A pops two VM values and performs value conversion/assignment')==0x1a
with open('/mnt/data/SjTNlCHNfW_verified_vm_trace.csv','w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(R[0]));w.writeheader();w.writerows(R)
print('trace rows',len(R),'sha256',hashlib.sha256(data).hexdigest())
