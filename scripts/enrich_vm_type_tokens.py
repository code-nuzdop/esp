"""Offline TypeRef name lookup using .NET metadata heaps, never loads EXE."""
import contextlib,io,csv
ns={}
with contextlib.redirect_stdout(io.StringIO()):
    exec(open('/mnt/data/inspect_sample_typerefs.py').read().split('for k in [1,2,84,85,254]:')[0],ns)
rows=list(csv.DictReader(open('/mnt/data/SjTNlCHNfW_verified_124_local_slots.csv',newline='')))
for row in rows:
    token=int(row['type_token'],16); table=token>>24; rid=token&0xffffff
    if table == 1 and 0<rid<=ns['typerefs']:
        ofs=ns['p']+(rid-1)*(ns['scopewidth']+2*ns['stringwidth'])
        scope=ns['scopewidth'];sw=ns['stringwidth']
        name=ns['getstr'](ns['readn'](ofs+scope,sw));namespace=ns['getstr'](ns['readn'](ofs+scope+sw,sw))
        row['resolved_type']=(namespace+'.' if namespace else '')+name
    elif table==2:row['resolved_type']='TypeDef (not resolved)'
    elif table==0x1b:row['resolved_type']='TypeSpec (not resolved)'
    else:row['resolved_type']='Unresolved'
with open('/mnt/data/SjTNlCHNfW_typed_124_local_slots.csv','w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
