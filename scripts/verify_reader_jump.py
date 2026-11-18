"""Read-only evidence verification for SjTNlCHNfW.exe.
Uses previously recovered opcode map and offline reader interpreter.
DOES NOT load or execute the managed PE.
"""
import csv, hashlib, pathlib, struct, sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from static_reader_emulator import Reader
base=pathlib.Path(__file__).resolve().parent
exe=base/'SjTNlCHNfW(1).exe'
assert hashlib.sha256(exe.read_bytes()).hexdigest() == '119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40'
ops=list(csv.DictReader(open(base/'vm_opcode_map.csv',newline='')))
def take(r,typ):
 addr=r.fields['D38A0391'];val,_=r.execute({'opcode':'0x060000D3','u32':'0x060000DB','u16':'0x060000D4'}[typ]);return addr,val
rows=[]
def trace(pos,sequence,name):
 r=Reader(pos)
 for kind,expected,description in sequence:
  addr,value=take(r,kind)
  assert value==expected,(name,kind,hex(addr),hex(value),hex(expected))
  rows.append({'stream':name,'rva_before':f'0x{addr:08X}','read_kind':kind,'value':f'0x{value:08X}', 'description':description,'handler':ops[value]['handler'] if kind=='opcode' else ''})
 print(name,'records',len(sequence),'end cursor',hex(r.fields['D38A0391']))
 return r
root=[
 ('opcode',0x10,'push uint32'),('u32',0,'integer 0'),('opcode',0x50,'stack discard'),('opcode',0x50,'stack discard'),
 ('opcode',0x10,'push uint32'),('u32',52,'array length 52'),('opcode',0x1B,'allocate typed array'),('u32',0x01000058,'System.UInt32'),
 ('opcode',0x01,'resolve VM value'),('u32',0,'value 0'),('opcode',0x12,'field reference'),('u32',0x04000182,'76B7C6BB.D0244F83 (static UInt32[])'),('opcode',0x1A,'typed assignment'),
 ('opcode',0xC3,'resolve VM value'),('u32',0,'value 0'),('opcode',0x10,'push uint32'),('u32',0,'integer 0'),('opcode',0x39,'wrapped cursor field reference'),('u32',0x04000191,'6633B699.B32A609B (A3B21017 reader)'),('opcode',0x1A,'typed assignment / possible cursor redirection')]
trace(0x7FC7AF,root,'76B7C6BB .cctor')
second=[('u16',0,'header count'),('u32',0x01000058,'System.UInt32'),('u32',0x01000066,'System.Enum'),
 ('opcode',0x10,'push'),('u32',0,'zero'),('opcode',0x50,'discard'),('opcode',0x50,'discard'),
 ('opcode',0xC3,'resolve VM value'),('u32',0,'zero'),('opcode',0x12,'field ref'),('u32',0x04000182,'static uint[]'),('opcode',0x0D,'convert'),('opcode',0x10,'push'),('u32',5,'array index'),('opcode',0x95,'array get'),('u32',0x01000058,'UInt32'),('opcode',0x24,'convert'),('u32',0x01000058,'UInt32'),('opcode',0x10,'push'),('u32',0,'zero'),('opcode',0x39,'cursor field wrapper'),('u32',0x04000191,'reader'),('opcode',0x1A,'typed assignment / possible cursor redirection')]
trace(0x7FE224,second,'second nested')
with open(base/'SjTNlCHNfW_new_reader_jump_evidence.csv','w',newline='') as f:
 writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
print('Wrote',len(rows),'verified decoded records')
