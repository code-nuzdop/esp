#!/usr/bin/env python3
"""Strictly verify repo manifest, original ZIP contents, and method/CFG counts.

This script never executes or imports the sample binary.
"""
from pathlib import Path
import hashlib, re, zipfile, csv, json

root=Path(__file__).resolve().parents[1]
manifest_file=root/"MANIFEST_SHA256.txt"
archive=root/"SjTNlCHNfW_MASTER_evidence_package.zip"
required={"README.md","AUDIT.json","README_START_HERE.md",
          "SjTNlCHNfW.exe","SjTNlCHNfW_MASTER_evidence_package.zip",
          "evidence/SjTNlCHNfW_function_inventory.csv",
          "evidence/SjTNlCHNfW_disassembly.il.txt",
          "evidence/SjTNlCHNfW_control_flow_graphs.json"}
def parse(lines, header=False):
    entries={}
    for number,raw in enumerate(lines,1):
        if not raw.strip() or raw.startswith("#") or (header and raw.startswith("SHA-256  FILE ")):
            continue
        match=re.fullmatch(r"([0-9a-fA-F]{64})  (.+)",raw)
        if not match: raise SystemExit(f"Malformed manifest line {number}: {raw[:80]!r}")
        sha,path=match.groups()
        if path in entries: raise SystemExit(f"Duplicate manifest entry: {path}")
        entries[path]=sha.lower()
    return entries
def sha(data):return hashlib.sha256(data).hexdigest()
repo=parse(manifest_file.read_text(encoding="utf-8").splitlines())
all_files=set()
for folder in ["evidence","report","scripts","historical",".github"]:
    all_files|={p.relative_to(root).as_posix() for p in (root/folder).rglob("*") if p.is_file()}
all_files|={p.relative_to(root).as_posix() for p in root.glob("*.txt") if p.name!="MANIFEST_SHA256.txt"}
all_files|={"README.md","README_START_HERE.md","AUDIT.json",
            "SjTNlCHNfW.exe","SjTNlCHNfW_MASTER_evidence_package.zip"}
if set(repo)!=all_files or not required<=set(repo):
    raise SystemExit(f"Root manifest missing={sorted(all_files-set(repo))}, extra={sorted(set(repo)-all_files)}")
for name,digest in repo.items():
    if sha((root/name).read_bytes())!=digest:raise SystemExit(f"Repository hash mismatch: {name}")
with zipfile.ZipFile(archive) as z:
    if z.testzip():raise SystemExit("ZIP CRC mismatch")
    member_files={n for n in z.namelist() if not n.endswith("/")}
    internal=parse(z.read("MANIFEST_SHA256.txt").decode("utf-8").splitlines(),header=True)
    if len(internal)<60 or set(internal)!=member_files-{"MANIFEST_SHA256.txt"}:
        raise SystemExit("ZIP internal manifest missing or truncated")
    for n,h in internal.items():
        if sha(z.read(n))!=h:raise SystemExit(f"ZIP member hash mismatch: {n}")
with (root/"evidence/SjTNlCHNfW_function_inventory.csv").open(encoding="utf-8-sig",newline="") as f:
    rows=list(csv.DictReader(f))
cfg=json.loads((root/"evidence/SjTNlCHNfW_control_flow_graphs.json").read_text(encoding="utf-8"))
if len(rows)!=888 or len(cfg)!=650:raise SystemExit(f"Method/CFG count mismatch: {len(rows)} / {len(cfg)}")
audit=json.loads((root/"AUDIT.json").read_text(encoding="utf-8"))
if sha((root/"SjTNlCHNfW.exe").read_bytes())!=audit["sample_sha256"]:
    raise SystemExit("Sample SHA-256 != AUDIT.json")
print(f"OK: {len(repo)} checked-in SHA-256 hashes, {len(internal)} ZIP member hashes, 888 methods, 650 CFGs")
