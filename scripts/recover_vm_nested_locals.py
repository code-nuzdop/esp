"""Read-only static reconstruction of the two nested VM segments.
Does NOT load or execute the suspicious EXE. Requires existing extracted IL and
static_reader_emulator.py from the analysis package. This intentionally stops
when an instruction could mutate the VM's bytecode reader object.
"""
import csv
from static_reader_emulator import Reader

MAP = list(csv.DictReader(open('/mnt/data/vm_opcode_map.csv', newline='')))

def take(r, kind):
    before = r.fields['D38A0391']
    result, _ = r.execute({'opcode': '0x060000D3', 'u32': '0x060000DB',
                           'u16': '0x060000D4', 'u8': '0x060000DE'}[kind])
    return before, result

# Replay only known, statically verified operand-reading signatures.
initial = Reader(0x80054A)
for kind in ('u16','u32','u32','opcode','u32','opcode','opcode',
             'u8','u32','u32','u32','u32','opcode','u8','u32','u32',
             'u32','u32','opcode','u32','opcode','u32','opcode'):
    take(initial,kind)
assert initial.fields['D38A0391'] == 0x80050B

local_rows = []
for index in range(124):
    begin, op1 = take(initial,'opcode')
    _, zero1 = take(initial,'u32')
    _, op2 = take(initial,'opcode')
    _, zero2 = take(initial,'u32')
    _, op3 = take(initial,'opcode')
    _, type_tok = take(initial,'u32')
    _, op4 = take(initial,'opcode')
    _, slot = take(initial,'u16')
    assert MAP[op1]['handler'].strip("'()") == 'B1190689'
    assert MAP[op2]['handler'].strip("'()") == 'B40B1435'
    assert MAP[op3]['handler'].strip("'()") == 'B40B1435'
    assert MAP[op4]['handler'].strip("'()") == '76862C12'
    assert zero1 == zero2 == 0 and slot == index
    local_rows.append({'slot':index,'start_rva':f'0x{begin:08X}',
                       'constant_opcode':f'0x{op1:02X}',
                       'first_push_opcode':f'0x{op2:02X}',
                       'second_push_opcode':f'0x{op3:02X}',
                       'type_token':f'0x{type_tok:08X}',
                       'assign_opcode':f'0x{op4:02X}',
                       'index_operand':slot})

_, discard = take(initial,'opcode')
_, push = take(initial,'opcode')
_, selector = take(initial,'u32')
_, call = take(initial,'opcode')
assert (discard,push,selector,call) == (0x50,0x10,0x7FE224,0x53)

with open('/mnt/data/SjTNlCHNfW_verified_124_local_slots.csv','w',newline='') as f:
    w = csv.DictWriter(f,fieldnames=list(local_rows[0]));w.writeheader();w.writerows(local_rows)

second = Reader(selector)
records=[]
for kind, expected, label in [
    ('u16',0x0,'header_count'),('u32',0x01000058,'header_type_a'),
    ('u32',0x01000066,'header_type_b'),
    ('opcode',0x10,'push'),('u32',0,'push_operand'),
    ('opcode',0x50,'discard'),('opcode',0x50,'discard'),
    ('opcode',0xC3,'resolve_push'),('u32',0,'resolve_operand'),
    ('opcode',0x12,'field_reference'),('u32',0x04000182,'field_operand'),
    ('opcode',0x0D,'unary_convert'),('opcode',0x10,'push'),
    ('u32',5,'push_operand'),('opcode',0x95,'array_get'),
    ('u32',0x01000058,'array_element_type'),
    ('opcode',0x24,'convert'),('u32',0x01000058,'convert_type'),
    ('opcode',0x10,'push'),('u32',0,'push_operand'),
    ('opcode',0x39,'field_reference'),('u32',0x04000191,'reader_field'),
    ('opcode',0x1A,'assignment_to_reader_field')]:
    pos,v=take(second,kind);assert v==expected,(label,hex(pos),hex(v),hex(expected))
    records.append({'cursor_rva':f'0x{pos:08X}','kind':kind,
                    'value':f'0x{v:08X}', 'meaning':label,
                    'handler':MAP[v]['handler'] if kind=='opcode' else ''})
with open('/mnt/data/SjTNlCHNfW_second_nested_trace.csv','w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
print('Recovered',len(local_rows),'sequential local slots; next nested selector',hex(selector))
print('Second nested records',len(records),'last cursor',hex(second.fields['D38A0391']))
print('STOP: 0x1A may replace VM reader; do not decode next byte from stale reader')
