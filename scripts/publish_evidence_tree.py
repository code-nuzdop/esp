#!/usr/bin/env python3
"""Publish the checked-in static-analysis archive as browseable evidence.
No sample or bundled script is executed.
"""
from pathlib import Path
import hashlib, json, zipfile, csv, codecs, shutil

root=Path(__file__).resolve().parents[1]
source=root/"SjTNlCHNfW_MASTER_evidence_package.zip"
if not source.is_file(): raise SystemExit("Original evidence snapshot is missing")
with zipfile.ZipFile(source) as z:
    bad=z.testzip()
    if bad: raise SystemExit(f"ZIP CRC mismatch: {bad}")
    entries={n for n in z.namelist() if not n.endswith("/")}
    required={"MANIFEST_SHA256.txt","evidence/SjTNlCHNfW_disassembly.il.txt",
              "evidence/SjTNlCHNfW_control_flow_graphs.json",
              "evidence/SjTNlCHNfW_function_inventory.csv"}
    if not required.issubset(entries): raise SystemExit("Incomplete archive")
    manifest=z.read("MANIFEST_SHA256.txt").decode("utf-8").splitlines()
    for line in manifest:
        digest, name=line.split("  ",1)
        if len(digest)!=64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
            continue  # Ignore explanatory manifest headers.
        if name not in entries or hashlib.sha256(z.read(name)).hexdigest()!=digest:
            raise SystemExit(f"Manifest mismatch: {name}")
    for name in sorted(entries):
        parts=Path(name)
        if parts.is_absolute() or ".." in parts.parts:
            raise SystemExit(f"Unexpected archive path: {name}")
        dest=root/parts
        dest.parent.mkdir(parents=True,exist_ok=True)
        # Preserve the repository's existing self-describing 888-row README.
        if name=="README.md" and dest.exists(): continue
        dest.write_bytes(z.read(name))

def normalize(path):
    raw=path.read_bytes()
    if raw.startswith((codecs.BOM_UTF16_LE,codecs.BOM_UTF16_BE)):
        decoded=raw.decode("utf-16")
    elif len(raw)>100 and raw[:512].count(b"\x00")>len(raw[:512])//5:
        odd=raw[1:512:2].count(b"\x00")
        even=raw[:512:2].count(b"\x00")
        decoded=raw.decode("utf-16-le" if odd>even else "utf-16-be")
    else: return False
    path.write_bytes(decoded.encode("utf-8"))
    return True

normalized=[]
for p in list(root.glob("*.txt"))+list((root/"evidence").rglob("*.txt")):
    if p.is_file() and normalize(p): normalized.append(str(p.relative_to(root)))

old=root/"report/SjTNlCHNfW_MASTER_comprehensive_report.md"
new=root/"report/SjTNlCHNfW_Loader_Protector_report.md"
if old.exists():
    body=old.read_text(encoding="utf-8-sig")
    scope="""# SjTNlCHNfW.exe — Loader + Protector Static Analysis and .NET VM Reverse Engineering

> **Scope:** The evidence describes the executable's managed loader/protection layer and partial VM decoding. It does **not** establish a working aimbot, ESP pipeline, or cheat payload. The 163 MethodDef RVAs in zero-raw executable sections are structurally unbacked in the on-disk image, but their runtime generation is **unverified**.

## Runtime-materialization hypothesis (not demonstrated)

The sections `F!_~Pyan` and `0[n6P0.A` have Code|Execute|Read flags (`0x60000020`) and no file-backed bytes. A write to these pages would require suitable memory protection at the time of writing, **if** protected code is actually materialized there. No `VirtualProtect` event or generated method body has been observed. The zero-filled entry-point RVA `0x2050` does not by itself prove a valid empty `Main` stub. The file-backed `<Module>::.cctor` at RVA `0xA988D8` is an independently verified early initializer. Reflection.Emit and unmanaged allocation references indicate **capability**, not proof of how the 163 declarations are handled.

The custom protector's product/vendor is **unidentified**. The 52-element `D0244F83` array, element 5, reader-cursor control, and the missing method bodies remain unresolved. No verified aimbot/ESP behavior can be asserted.

---

"""
    new.write_text(scope+body,encoding="utf-8")
    old.unlink()
# Preserve the outdated PDF as historical evidence; do not present it as the corrected report.
pdf=root/"report/SjTNlCHNfW_MASTER_comprehensive_report.pdf"
if pdf.exists():
    target=root/"historical/reports/SjTNlCHNfW_MASTER_comprehensive_report_superseded.pdf"
    target.parent.mkdir(parents=True,exist_ok=True)
    if not target.exists(): shutil.copy2(pdf,target)
    pdf.unlink()

readme=root/"README.md"
if readme.exists():
    content=readme.read_text(encoding="utf-8-sig")
    note="""<!-- Scope and browseable evidence tree published from the checked-in archive. -->
**Repository navigation:** [Corrected loader/protector report](report/SjTNlCHNfW_Loader_Protector_report.md) · [888-row method CSV](evidence/SjTNlCHNfW_function_inventory.csv) · [Full IL disassembly](evidence/SjTNlCHNfW_disassembly.il.txt) · [CFG JSON](evidence/SjTNlCHNfW_control_flow_graphs.json) · [Audit](AUDIT.json) · [Integrity manifest](MANIFEST_SHA256.txt).

**Important:** This analyzes the loader/protector, not verified aimbot/ESP behavior. The 163 unbacked method RVAs do not prove generated bodies, and the protector is not attributed to a vendor.

"""
    if "<!-- Scope and browseable evidence tree" not in content:
        readme.write_text(note+content,encoding="utf-8")

inventory=root/"evidence/SjTNlCHNfW_function_inventory.csv"
with inventory.open(newline="",encoding="utf-8-sig") as f: rows=list(csv.DictReader(f))
cfg=json.loads((root/"evidence/SjTNlCHNfW_control_flow_graphs.json").read_text(encoding="utf-8"))
sample=root/"SjTNlCHNfW.exe"
audit={
 "scope":"Loader + protector static analysis; runtime generation and cheat payload unverified",
 "sample_sha256":hashlib.sha256(sample.read_bytes()).hexdigest() if sample.exists() else None,
 "sample_size":sample.stat().st_size if sample.exists() else None,
 "method_inventory_rows":len(rows),
 "full_il_disassembly":"evidence/SjTNlCHNfW_disassembly.il.txt",
 "cfg_json":"evidence/SjTNlCHNfW_control_flow_graphs.json",
 "cfg_top_level_entries":len(cfg) if isinstance(cfg,(list,dict)) else None,
 "original_archive_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),
 "archive_manifest_entries":len(manifest),
 "archive_integrity_verified":True,
 "normalized_files":normalized
}
(root/"AUDIT.json").write_text(json.dumps(audit,indent=2)+"\n",encoding="utf-8")
files=[]
for folder in ["evidence","report","scripts","historical"]:
    files += [p for p in (root/folder).rglob("*") if p.is_file()]
files += [root/"README_START_HERE.md",root/"AUDIT.json"]
lines=[]
for p in sorted(set(files)):
    rel=p.relative_to(root).as_posix()
    lines.append(hashlib.sha256(p.read_bytes()).hexdigest()+"  "+rel)
(root/"MANIFEST_SHA256.txt").write_text("\n".join(lines)+"\n",encoding="utf-8")
print(f"Validated archive; published {len(files)} evidence files; {len(rows)} methods; normalized {len(normalized)} UTF-16 files")
