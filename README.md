# SjTNlCHNfW.exe — Loader + Protector Analysis
**SHA-256:** `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`  
**MVID:** `25c98968-dcee-4c45-889d-f1773ecb3789`  
**Sample size:** 6,783,488 bytes  
**CLR metadata:** 888 MethodDef rows  

> **Scope:** This repository documents static loader/protector behavior, obfuscated .NET VM implementation, and recovered metadata. It **does not** establish aimbot/ESP or other cheat functionality. The protected program has not been fully devirtualized or classified as benign/malicious. Do not execute the sample outside an isolated investigation environment.
## What this repository contains
- **`report/SjTNlCHNfW_MASTER_comprehensive_report.md`** — authoritative technical narrative (no PDF required).
- **`evidence/SjTNlCHNfW_recovery_status.csv`** — all 888 MethodDef rows with token, RVA, backing, IL status, instruction/block/edge counts, incoming calls, and analyst notes.
- **`evidence/SjTNlCHNfW_function_inventory.csv`** and **`evidence/SjTNlCHNfW_pass6_method_provenance.csv`** — independent 888-row inventories.
- **`evidence/SjTNlCHNfW_disassembly.il.txt`** — actual structural IL disassembly for all 650 file-backed methods (not devirtualized payload source).
- **`evidence/SjTNlCHNfW_control_flow_graphs.json`** — 650 CFGs, 2,725 basic blocks, 3,348 edges.
- **`evidence/SjTNlCHNfW_call_edges.csv`** — 2,561 syntactic calls; reachability is not established.
- **`evidence/vm_opcode_map.csv`** — 256 opcode keys to 93 distinct handler methods.
- **`evidence/SjTNlCHNfW_typed_124_local_slots.csv`** — the 124 reconstructed local registrations.
- **`scripts/`** — offline decoding and audit scripts; **`historical/`** preserves earlier analyses, including superseded hypotheses.
- **`MANIFEST_SHA256.txt`** and **`AUDIT.json`** — integrity and archive-content validation.

## What the 888-row inventory actually proves
| Metadata classification | Count | Interpretation |
|---|---:|---|
| File-backed decoded IL | 650 | Recoverable *structural* instruction bodies |
| Declared RVA in virtual-only region | 163 | Method bodies not present as raw file bytes at declared RVAs |
| Zero RVA | 75 | Includes abstract, runtime, and interop declarations; not 75 missing encrypted bodies |
| **Total MethodDef rows** | **888** | Direct CLR metadata row count |

The method token is a `0x06xxxxxx` MethodDef identifier. MVID identifies the managed module build and is **not** a sample-file cryptographic hash; verify the SHA-256 separately. The two supplied copies of the EXE have the same SHA-256. The sample binary and earlier process dump are deliberately excluded from the ZIP.

## Independent archive verification
- Exactly **650 distinct MethodDef headers** in the full IL disassembly; exact token-set match against the file-backed decoded subset of the 888-row inventory.
- Exactly **650 CFG entries**, with **2,725 blocks** and **3,348 edges**; exact matching MethodDef token set.
- **2,561** parsed call references, **256** opcode registrations, **93** distinct callbacks and **124** recovered VM local slots.
- All **41** explicit / expanded Appendix E filename claims are present. ZIP integrity checked with CRC.
- **8** historical UTF-16 text exports normalized to UTF-8 (without BOM) inside `evidence/`; nested historical ZIPs are retained byte-for-byte for provenance.

## Reading the method CSV without the PDF
`evidence/SjTNlCHNfW_recovery_status.csv` has the columns: `method_token`, `method_id`, `type`, `name`, `rva`, `file_backing`, `header`, `il_decode`, `instructions`, `basic_blocks`, `cfg_edges`, `internal_incoming_calls`, `notes`. Every MethodDef row is also indexed below for convenient source browsing; numerical measurements and notes remain in the CSV.

<details>
<summary>Expand all 888 methods (token, type, name, RVA, backing, decode state)</summary>

| Token | Type | Name | RVA | Backing | IL decode |
|---|---|---|---|---|---|
| 0x06000001 | <Module> | .cctor | 0x00A988D8 | file-backed | decoded |
| 0x06000002 | DB884EB1 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000003 | DB884EB1 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000004 | DB884EB1 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000005 | DB884EB1 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000006 | 47BFADB7 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000007 | 47BFADB7 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000008 | 47BFADB7 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000009 | 47BFADB7 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x0600000A | 16040A14 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600000B | 16040A14 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x0600000C | 16040A14 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600000D | 16040A14 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x0600000E | 022C8832 | 798B5EB6 | 0x00E5A314 | file-backed | decoded |
| 0x0600000F | 022C8832 | 2683EF81 | 0x00E5A3E4 | file-backed | decoded |
| 0x06000010 | 022C8832 | 958D7532 | 0x00E5A3A4 | file-backed | decoded |
| 0x06000011 | 022C8832 | 9F0A88B4 | 0x00E5A424 | file-backed | decoded |
| 0x06000012 | 022C8832 | F187C6B4 | 0x00E5A400 | file-backed | decoded |
| 0x06000013 | 022C8832 | BE8EDF2B | 0x00E5A3C8 | file-backed | decoded |
| 0x06000014 | 022C8832 | DDAEE803 | 0x00E5A2DC | file-backed | decoded |
| 0x06000015 | 022C8832 | DF8FD725 | 0x00E5A368 | file-backed | decoded |
| 0x06000016 | 022C8832 | 5F11D60F | 0x00E5A334 | file-backed | decoded |
| 0x06000017 | 022C8832 | 1C11229E | 0x00E5A2F4 | file-backed | decoded |
| 0x06000018 | 022C8832 | AE814AAA | 0x00E5A390 | file-backed | decoded |
| 0x06000019 | 022C8832 | .ctor | 0x00E5A29C | file-backed | decoded |
| 0x0600001A | C5A2642F | BAA7432D | 0x003E73D0 | virtual-only | unavailable |
| 0x0600001B | C5A2642F | B105A3A9 | 0x003E73E8 | virtual-only | unavailable |
| 0x0600001C | C5A2642F | F91108BB | 0x003E7394 | virtual-only | unavailable |
| 0x0600001D | C5A2642F | 4EA5DB9F | 0x003E73C5 | virtual-only | unavailable |
| 0x0600001E | C5A2642F | CF07FE3F | 0x003E73DC | virtual-only | unavailable |
| 0x0600001F | C5A2642F | 1C0FD2B2 | 0x003E7358 | virtual-only | unavailable |
| 0x06000020 | C5A2642F | FA0A1D03 | 0x003E73BB | virtual-only | unavailable |
| 0x06000021 | C5A2642F | 8E3559B6 | 0x003E73C9 | virtual-only | unavailable |
| 0x06000022 | C5A2642F | DDBC5192 | 0x003E72F8 | virtual-only | unavailable |
| 0x06000023 | BA108E2E | 1D93B236 | 0x00002050 | virtual-only | unavailable |
| 0x06000024 | BA108E2E | 4A8F3781 | 0x0000208C | virtual-only | unavailable |
| 0x06000025 | BA108E2E | 9E978981 | 0x00002098 | virtual-only | unavailable |
| 0x06000026 | BA108E2E | B00640B3 | 0x007F3A00 | virtual-only | broken |
| 0x06000027 | BA108E2E | .ctor | 0x000021E3 | virtual-only | unavailable |
| 0x06000028 | BA108E2E | OnCreateMainForm | 0x0000221A | virtual-only | broken |
| 0x06000029 | ED16602B | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600002A | ED16602B | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600002B | ED16602B | Invoke | 0x00000000 | no RVA | unavailable |
| 0x0600002C | ED16602B | .ctor | 0x00000000 | no RVA | unavailable |
| 0x0600002D | 5D8D6E97 | 9F0A88B4 | 0x00E5A5F8 | file-backed | decoded |
| 0x0600002E | 5D8D6E97 | DF8FD725 | 0x00E5A52C | file-backed | decoded |
| 0x0600002F | 5D8D6E97 | BE8EDF2B | 0x00E5A5A4 | file-backed | decoded |
| 0x06000030 | 5D8D6E97 | 5F11D60F | 0x00E5A50C | file-backed | decoded |
| 0x06000031 | 5D8D6E97 | DDAEE803 | 0x00E5A498 | file-backed | decoded |
| 0x06000032 | 5D8D6E97 | 798B5EB6 | 0x00E5A4E4 | file-backed | decoded |
| 0x06000033 | 5D8D6E97 | 2683EF81 | 0x00E5A5C0 | file-backed | decoded |
| 0x06000034 | 5D8D6E97 | 958D7532 | 0x00E5A580 | file-backed | decoded |
| 0x06000035 | 5D8D6E97 | F187C6B4 | 0x00E5A5DC | file-backed | decoded |
| 0x06000036 | 5D8D6E97 | AE814AAA | 0x00E5A554 | file-backed | decoded |
| 0x06000037 | 5D8D6E97 | 1C11229E | 0x00E5A4B8 | file-backed | decoded |
| 0x06000038 | 5D8D6E97 | .ctor | 0x00E5A440 | file-backed | decoded |
| 0x06000039 | 50B2440C | 61085517 | 0x00E5D958 | file-backed | decoded |
| 0x0600003A | 50B2440C | 798B5EB6 | 0x00E5D1E8 | file-backed | decoded |
| 0x0600003B | 50B2440C | D20CC905 | 0x00E5DA34 | file-backed | decoded |
| 0x0600003C | 50B2440C | 9F0A88B4 | 0x00E5DA0C | file-backed | decoded |
| 0x0600003D | 50B2440C | 5F11D60F | 0x00E5D4EC | file-backed | decoded |
| 0x0600003E | 50B2440C | 8F21799C | 0x00E5DB38 | file-backed | decoded |
| 0x0600003F | 50B2440C | DC1F9B0B | 0x00E5DA8C | file-backed | decoded |
| 0x06000040 | 50B2440C | 2683EF81 | 0x00E5D9E4 | file-backed | decoded |
| 0x06000041 | 50B2440C | AE814AAA | 0x00E5D8F4 | file-backed | decoded |
| 0x06000042 | 50B2440C | C081219E | 0x00E5DA5C | file-backed | decoded |
| 0x06000043 | 50B2440C | F187C6B4 | 0x00E5D938 | file-backed | decoded |
| 0x06000044 | 50B2440C | 1C11229E | 0x00E5D1A4 | file-backed | decoded |
| 0x06000045 | 50B2440C | F69CF28E | 0x00E5DAC4 | file-backed | decoded |
| 0x06000046 | 50B2440C | DDAEE803 | 0x00E5D184 | file-backed | decoded |
| 0x06000047 | 50B2440C | DAB8483B | 0x00E5D98C | file-backed | decoded |
| 0x06000048 | 50B2440C | 958D7532 | 0x00E5D9C4 | file-backed | decoded |
| 0x06000049 | 50B2440C | BE8EDF2B | 0x00E5D910 | file-backed | decoded |
| 0x0600004A | 50B2440C | .ctor | 0x00E5D12C | file-backed | decoded |
| 0x0600004B | 432CB414 | .ctor | 0x0000222E | virtual-only | unavailable |
| 0x0600004C | FD8B312A | .ctor | 0x00E47BBC | file-backed | decoded |
| 0x0600004D | FD8B312A | F42BCE2E | 0x00E47B40 | file-backed | decoded |
| 0x0600004E | FD8B312A | 95B0748C | 0x00E47B2C | file-backed | decoded |
| 0x0600004F | FD8B312A | 1B31E422 | 0x00E47ADC | file-backed | decoded |
| 0x06000050 | E29CB52C | 798B5EB6 | 0x00E5C2C0 | file-backed | decoded |
| 0x06000051 | E29CB52C | A8A96682 | 0x00E5C7D4 | file-backed | decoded |
| 0x06000052 | E29CB52C | C081219E | 0x00E5C480 | file-backed | decoded |
| 0x06000053 | E29CB52C | 8F21799C | 0x00E5C4F0 | file-backed | decoded |
| 0x06000054 | E29CB52C | F69CF28E | 0x00E5C4CC | file-backed | decoded |
| 0x06000055 | E29CB52C | 90A48EA4 | 0x00E5C78C | file-backed | decoded |
| 0x06000056 | E29CB52C | 230B3CA3 | 0x00E5C334 | file-backed | decoded |
| 0x06000057 | E29CB52C | 958D7532 | 0x00E5C3F8 | file-backed | decoded |
| 0x06000058 | E29CB52C | 2683EF81 | 0x00E5C418 | file-backed | decoded |
| 0x06000059 | E29CB52C | 5A87491B | 0x00E5C844 | file-backed | decoded |
| 0x0600005A | E29CB52C | BE8EDF2B | 0x00E5C390 | file-backed | decoded |
| 0x0600005B | E29CB52C | 821D0BA6 | 0x00E5C518 | file-backed | decoded |
| 0x0600005C | E29CB52C | 9CA5D91E | 0x00E5C1F4 | file-backed | decoded |
| 0x0600005D | E29CB52C | 41920DB8 | 0x00E5C5F4 | file-backed | decoded |
| 0x0600005E | E29CB52C | DC1F9B0B | 0x00E5C4B4 | file-backed | decoded |
| 0x0600005F | E29CB52C | D20CC905 | 0x00E5C460 | file-backed | decoded |
| 0x06000060 | E29CB52C | F187C6B4 | 0x00E5C3B8 | file-backed | decoded |
| 0x06000061 | E29CB52C | A216E8AE | 0x00E5C70C | file-backed | decoded |
| 0x06000062 | E29CB52C | DDAEE803 | 0x00E5C274 | file-backed | decoded |
| 0x06000063 | E29CB52C | 61085517 | 0x00E5C3D0 | file-backed | decoded |
| 0x06000064 | E29CB52C | 68360417 | 0x00E5C6A8 | file-backed | decoded |
| 0x06000065 | E29CB52C | 1002F78E | 0x00E5C580 | file-backed | decoded |
| 0x06000066 | E29CB52C | 5F11D60F | 0x00E5C2E8 | file-backed | decoded |
| 0x06000067 | E29CB52C | AE814AAA | 0x00E5C368 | file-backed | decoded |
| 0x06000068 | E29CB52C | 93AC8836 | 0x00E5C8C4 | file-backed | decoded |
| 0x06000069 | E29CB52C | 9F0A88B4 | 0x00E5C438 | file-backed | decoded |
| 0x0600006A | E29CB52C | D099F0B5 | 0x00E5C658 | file-backed | decoded |
| 0x0600006B | E29CB52C | 1C11229E | 0x00E5C28C | file-backed | decoded |
| 0x0600006C | E29CB52C | .ctor | 0x00E5C18C | file-backed | decoded |
| 0x0600006D | EAA46804 | CD90E311 | 0x00000000 | no RVA | unavailable |
| 0x0600006E | EAA46804 | .ctor | 0x00E5DFB8 | file-backed | decoded |
| 0x0600006F | EAA46804 | 841E011C | 0x00000000 | no RVA | unavailable |
| 0x06000070 | FB9C7B25 | 8AA7BB81 | 0x00E5E5E4 | file-backed | decoded |
| 0x06000071 | FB9C7B25 | 93329331 | 0x00E5E680 | file-backed | decoded |
| 0x06000072 | FB9C7B25 | 4D35DF1E | 0x00E5E794 | file-backed | decoded |
| 0x06000073 | FB9C7B25 | E2B967AD | 0x00E5E718 | file-backed | decoded |
| 0x06000074 | FB9C7B25 | E61629A6 | 0x00E5E63C | file-backed | decoded |
| 0x06000075 | FB9C7B25 | CD90E311 | 0x00E5E510 | file-backed | decoded |
| 0x06000076 | FB9C7B25 | .ctor | 0x00E5E888 | file-backed | decoded |
| 0x06000077 | FB9C7B25 | 21A7D23C | 0x00E5E80C | file-backed | decoded |
| 0x06000078 | FB9C7B25 | 841E011C | 0x00E5E4F0 | file-backed | decoded |
| 0x06000079 | 631F38A4 | 5A08923B | 0x00E54F60 | file-backed | decoded |
| 0x0600007A | 631F38A4 | C01E0F1A | 0x00E54F38 | file-backed | decoded |
| 0x0600007B | 631F38A4 | 5F14539E | 0x00E54EC4 | file-backed | decoded |
| 0x0600007C | 631F38A4 | 7DAAC2B9 | 0x00E54F88 | file-backed | decoded |
| 0x0600007D | 631F38A4 | 82B7370F | 0x00E54F10 | file-backed | decoded |
| 0x0600007E | 631F38A4 | 9B848DB4 | 0x00E54EB0 | file-backed | decoded |
| 0x0600007F | 95969DA2 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000080 | 95969DA2 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000081 | 95969DA2 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000082 | 95969DA2 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000083 | 9CB31104 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000084 | 9CB31104 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000085 | 9CB31104 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000086 | 9CB31104 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000087 | 20966122 | E8BBFE2F | 0x003EFEAD | virtual-only | unavailable |
| 0x06000088 | 20966122 | B223CBAF | 0x003EFCE7 | virtual-only | unavailable |
| 0x06000089 | 20966122 | 1D866A32 | 0x003EFCCA | virtual-only | unavailable |
| 0x0600008A | 20966122 | F01F6F01 | 0x003EFEA4 | virtual-only | unavailable |
| 0x0600008B | 20966122 | 1507E587 | 0x003EFEB5 | virtual-only | broken |
| 0x0600008C | 20966122 | .ctor | 0x003EFEBE | virtual-only | unavailable |
| 0x0600008D | 20966122 | 61A9EE85 | 0x003EFCFC | virtual-only | unavailable |
| 0x0600008E | 20966122 | 58975F83 | 0x003EFE9C | virtual-only | unavailable |
| 0x0600008F | 20966122 | 9B8CAF8F | 0x003EFC60 | virtual-only | broken |
| 0x06000090 | 2E18379F | .cctor | 0x00002238 | virtual-only | unavailable |
| 0x06000091 | 2E18379F | 9B0D76BD | 0x0000226C | virtual-only | unavailable |
| 0x06000092 | 2E18379F | B2A9A031 | 0x00002288 | virtual-only | unavailable |
| 0x06000093 | 2E18379F | 6090AC9B | 0x000022A4 | virtual-only | unavailable |
| 0x06000094 | 2E18379F | 583CB68B | 0x000022C0 | virtual-only | unavailable |
| 0x06000095 | 2E18379F | FC029FA1 | 0x000022DC | virtual-only | unavailable |
| 0x06000096 | 7B233F0D | DC1F9B0B | 0x00E5D048 | file-backed | decoded |
| 0x06000097 | 7B233F0D | 798B5EB6 | 0x00E5CE70 | file-backed | decoded |
| 0x06000098 | 7B233F0D | 8635DBB2 | 0x00E5CD40 | file-backed | decoded |
| 0x06000099 | 7B233F0D | BE8EDF2B | 0x00E5CF40 | file-backed | decoded |
| 0x0600009A | 7B233F0D | 8F21799C | 0x00E5D0C0 | file-backed | decoded |
| 0x0600009B | 7B233F0D | DDAEE803 | 0x00E5CE38 | file-backed | decoded |
| 0x0600009C | 7B233F0D | 9F0A88B4 | 0x00E5CFA0 | file-backed | decoded |
| 0x0600009D | 7B233F0D | 61085517 | 0x00E5CFC0 | file-backed | decoded |
| 0x0600009E | 7B233F0D | D20CC905 | 0x00E5CFE8 | file-backed | decoded |
| 0x0600009F | 7B233F0D | 5F11D60F | 0x00E5CE94 | file-backed | decoded |
| 0x060000A0 | 7B233F0D | F187C6B4 | 0x00E5CF88 | file-backed | decoded |
| 0x060000A1 | 7B233F0D | 2683EF81 | 0x00E5CF68 | file-backed | decoded |
| 0x060000A2 | 7B233F0D | AE814AAA | 0x00E5CF28 | file-backed | decoded |
| 0x060000A3 | 7B233F0D | 958D7532 | 0x00E5CF08 | file-backed | decoded |
| 0x060000A4 | 7B233F0D | C081219E | 0x00E5D018 | file-backed | decoded |
| 0x060000A5 | 7B233F0D | F69CF28E | 0x00E5D070 | file-backed | decoded |
| 0x060000A6 | 7B233F0D | 1C11229E | 0x00E5CE58 | file-backed | decoded |
| 0x060000A7 | 7B233F0D | .ctor | 0x00E5CCB8 | file-backed | decoded |
| 0x060000A8 | CE2B360D | F618E1B0 | 0x00E47D0C | file-backed | decoded |
| 0x060000A9 | CE2B360D | 0906988E | 0x00E47DE4 | file-backed | decoded |
| 0x060000AA | CE2B360D | 0D18C907 | 0x00E47D48 | file-backed | decoded |
| 0x060000AB | CE2B360D | AE9B8ABF | 0x00E47D94 | file-backed | decoded |
| 0x060000AC | CE2B360D | .ctor | 0x00E47CE4 | file-backed | decoded |
| 0x060000AD | 5086C906 | E2900823 | 0x00E481E8 | file-backed | decoded |
| 0x060000AE | 5086C906 | .cctor | 0x00E48038 | file-backed | decoded |
| 0x060000AF | E4113232 | 798B5EB6 | 0x00E5DF14 | file-backed | decoded |
| 0x060000B0 | E4113232 | 5F11D60F | 0x00E5DF48 | file-backed | decoded |
| 0x060000B1 | E4113232 | 1C11229E | 0x00E5DED8 | file-backed | decoded |
| 0x060000B2 | E4113232 | DDAEE803 | 0x00E5DEC0 | file-backed | decoded |
| 0x060000B3 | E4113232 | .ctor | 0x00E5DE48 | file-backed | decoded |
| 0x060000B4 | BDAFD2B1 | 2683EF81 | 0x00E5A8C0 | file-backed | decoded |
| 0x060000B5 | BDAFD2B1 | 798B5EB6 | 0x00E5A7E0 | file-backed | decoded |
| 0x060000B6 | BDAFD2B1 | DDAEE803 | 0x00E5A798 | file-backed | decoded |
| 0x060000B7 | BDAFD2B1 | DF8FD725 | 0x00E5A838 | file-backed | decoded |
| 0x060000B8 | BDAFD2B1 | 958D7532 | 0x00E5A87C | file-backed | decoded |
| 0x060000B9 | BDAFD2B1 | 5F11D60F | 0x00E5A808 | file-backed | decoded |
| 0x060000BA | BDAFD2B1 | BE8EDF2B | 0x00E5A8A4 | file-backed | decoded |
| 0x060000BB | BDAFD2B1 | AE814AAA | 0x00E5A858 | file-backed | decoded |
| 0x060000BC | BDAFD2B1 | F187C6B4 | 0x00E5A8D4 | file-backed | decoded |
| 0x060000BD | BDAFD2B1 | 9F0A88B4 | 0x00E5A8E8 | file-backed | decoded |
| 0x060000BE | BDAFD2B1 | 1C11229E | 0x00E5A7C0 | file-backed | decoded |
| 0x060000BF | BDAFD2B1 | .ctor | 0x00E5A75C | file-backed | decoded |
| 0x060000C0 | A229A604 | 6488262D | 0x007F3B44 | virtual-only | unavailable |
| 0x060000C1 | A229A604 | 1C290DBC | 0x00002340 | virtual-only | unavailable |
| 0x060000C2 | A229A604 | 49382AAE | 0x00002357 | virtual-only | unavailable |
| 0x060000C3 | A229A604 | 928F283C | 0x00002360 | virtual-only | unavailable |
| 0x060000C4 | A229A604 | B9171606 | 0x007F3B98 | virtual-only | unavailable |
| 0x060000C5 | A229A604 | 7723DF2B | 0x000023C8 | virtual-only | unavailable |
| 0x060000C6 | A229A604 | D9ADE997 | 0x007F3BD4 | virtual-only | broken |
| 0x060000C7 | A8940832 | D587F411 | 0x00E56B60 | file-backed | decoded |
| 0x060000C8 | A8940832 | 9FB3088F | 0x00E56650 | file-backed | decoded |
| 0x060000C9 | A8940832 | .ctor | 0x00E56D2C | file-backed | decoded |
| 0x060000CA | A8940832 | 4223210F | 0x00E56C44 | file-backed | decoded |
| 0x060000CB | A8940832 | F70F8736 | 0x00E565B8 | file-backed | decoded |
| 0x060000CC | C08BBCAB | DDAEE803 | 0x00E5C0B4 | file-backed | decoded |
| 0x060000CD | C08BBCAB | F69CF28E | 0x00E5C144 | file-backed | decoded |
| 0x060000CE | C08BBCAB | 1C11229E | 0x00E5C0DC | file-backed | decoded |
| 0x060000CF | C08BBCAB | 798B5EB6 | 0x00E5C0FC | file-backed | decoded |
| 0x060000D0 | C08BBCAB | 5F11D60F | 0x00E5C110 | file-backed | decoded |
| 0x060000D1 | C08BBCAB | .ctor | 0x00E5C060 | file-backed | decoded |
| 0x060000D2 | A3B21017 | 8E854134 | 0x00E5E950 | file-backed | decoded |
| 0x060000D3 | A3B21017 | 27803C38 | 0x00E5EA50 | file-backed | decoded |
| 0x060000D4 | A3B21017 | 3EA86035 | 0x00E5EDA8 | file-backed | decoded |
| 0x060000D5 | A3B21017 | 9DA5A620 | 0x00E5E9C8 | file-backed | decoded |
| 0x060000D6 | A3B21017 | 6F3781B6 | 0x00E5F0D0 | file-backed | decoded |
| 0x060000D7 | A3B21017 | CD90E311 | 0x00E5E8F4 | file-backed | decoded |
| 0x060000D8 | A3B21017 | 353DF40D | 0x00E5F160 | file-backed | decoded |
| 0x060000D9 | A3B21017 | 2B35DA01 | 0x00E5F134 | file-backed | decoded |
| 0x060000DA | A3B21017 | 1A960EBF | 0x00E5E980 | file-backed | decoded |
| 0x060000DB | A3B21017 | 5B08298E | 0x00E5EEE8 | file-backed | decoded |
| 0x060000DC | A3B21017 | .ctor | 0x00E5F18C | file-backed | decoded |
| 0x060000DD | A3B21017 | 502DC297 | 0x00E5EA38 | file-backed | decoded |
| 0x060000DE | A3B21017 | 598A34AE | 0x00E5EC74 | file-backed | decoded |
| 0x060000DF | A3B21017 | 841E011C | 0x00E5E8D8 | file-backed | decoded |
| 0x060000E0 | F49AF186 | CB890B8A | 0x00E5DC30 | file-backed | decoded |
| 0x060000E1 | F49AF186 | 21BA5F2E | 0x00E5DC14 | file-backed | decoded |
| 0x060000E2 | F49AF186 | 3C087C01 | 0x00E5DBF8 | file-backed | decoded |
| 0x060000E3 | F49AF186 | .ctor | 0x00E5DBA4 | file-backed | decoded |
| 0x060000E4 | E59C751A | 252565BC | 0x003F35F7 | virtual-only | unavailable |
| 0x060000E5 | E59C751A | .ctor | 0x003F35EF | virtual-only | unavailable |
| 0x060000E6 | E59C751A | .cctor | 0x003F35E3 | virtual-only | unavailable |
| 0x060000E7 | CB08A9A2 | 6902CA30 | 0x007F5044 | virtual-only | unavailable |
| 0x060000E8 | CB08A9A2 | BB1C392E | 0x007F514C | virtual-only | unavailable |
| 0x060000E9 | CB08A9A2 | .ctor | 0x007F5018 | virtual-only | unavailable |
| 0x060000EA | A5A0BDA6 | 5F11D60F | 0x00E5B320 | file-backed | decoded |
| 0x060000EB | A5A0BDA6 | 1C11229E | 0x00E5B2C4 | file-backed | decoded |
| 0x060000EC | A5A0BDA6 | DF8FD725 | 0x00E5B25C | file-backed | decoded |
| 0x060000ED | A5A0BDA6 | 798B5EB6 | 0x00E5B30C | file-backed | decoded |
| 0x060000EE | A5A0BDA6 | DDAEE803 | 0x00E5B2A8 | file-backed | decoded |
| 0x060000EF | A5A0BDA6 | .ctor | 0x00E5B218 | file-backed | decoded |
| 0x060000F0 | 752159AD | ToString | 0x007F5E04 | virtual-only | unavailable |
| 0x060000F1 | 752159AD | .ctor | 0x007F5DD8 | virtual-only | unavailable |
| 0x060000F2 | 43233FA0 | F69CF28E | 0x00E59658 | file-backed | decoded |
| 0x060000F3 | 43233FA0 | F187C6B4 | 0x00E59528 | file-backed | decoded |
| 0x060000F4 | 43233FA0 | 2BA3942E | 0x00E5977C | file-backed | decoded |
| 0x060000F5 | 43233FA0 | AE814AAA | 0x00E594E8 | file-backed | decoded |
| 0x060000F6 | 43233FA0 | 8F21799C | 0x00E596C8 | file-backed | decoded |
| 0x060000F7 | 43233FA0 | DC1F9B0B | 0x00E59634 | file-backed | decoded |
| 0x060000F8 | 43233FA0 | A229B4BC | 0x00E59864 | file-backed | decoded |
| 0x060000F9 | 43233FA0 | 820CD514 | 0x00E59804 | file-backed | decoded |
| 0x060000FA | 43233FA0 | E43B02BB | 0x00E59940 | file-backed | decoded |
| 0x060000FB | 43233FA0 | 230B3CA3 | 0x00E594D0 | file-backed | decoded |
| 0x060000FC | 43233FA0 | DAB8483B | 0x00E59560 | file-backed | decoded |
| 0x060000FD | 43233FA0 | 2683EF81 | 0x00E595A8 | file-backed | decoded |
| 0x060000FE | 43233FA0 | DDAEE803 | 0x00E59438 | file-backed | decoded |
| 0x060000FF | 43233FA0 | 958D7532 | 0x00E59584 | file-backed | decoded |
| 0x06000100 | 43233FA0 | 798B5EB6 | 0x00E59488 | file-backed | decoded |
| 0x06000101 | 43233FA0 | BE8EDF2B | 0x00E59504 | file-backed | decoded |
| 0x06000102 | 43233FA0 | 42352CAA | 0x00E599E4 | file-backed | decoded |
| 0x06000103 | 43233FA0 | 61085517 | 0x00E59544 | file-backed | decoded |
| 0x06000104 | 43233FA0 | 1C11229E | 0x00E59460 | file-backed | decoded |
| 0x06000105 | 43233FA0 | C081219E | 0x00E59620 | file-backed | decoded |
| 0x06000106 | 43233FA0 | FF0A0DA7 | 0x00E59744 | file-backed | decoded |
| 0x06000107 | 43233FA0 | D20CC905 | 0x00E595FC | file-backed | decoded |
| 0x06000108 | 43233FA0 | 5F11D60F | 0x00E594B0 | file-backed | decoded |
| 0x06000109 | 43233FA0 | C906C88E | 0x00E597BC | file-backed | decoded |
| 0x0600010A | 43233FA0 | 873F0715 | 0x00E59844 | file-backed | decoded |
| 0x0600010B | 43233FA0 | 9F0A88B4 | 0x00E595CC | file-backed | decoded |
| 0x0600010C | 43233FA0 | .ctor | 0x00E59408 | file-backed | decoded |
| 0x0600010D | MySettings | .cctor | 0x0000242E | virtual-only | unavailable |
| 0x0600010E | MySettings | .ctor | 0x00002453 | virtual-only | unavailable |
| 0x0600010F | MySettings | E9AF4B0D | 0x0000245C | virtual-only | unavailable |
| 0x06000110 | MySettings | 14B50F81 | 0x00002488 | virtual-only | unavailable |
| 0x06000111 | 548C718A | C83786A3 | 0x00E475A8 | file-backed | decoded |
| 0x06000112 | 548C718A | 0C215086 | 0x00E47A60 | file-backed | decoded |
| 0x06000113 | 548C718A | AC33321F | 0x00E47530 | file-backed | decoded |
| 0x06000114 | 548C718A | A38C9124 | 0x00E474E0 | file-backed | decoded |
| 0x06000115 | 548C718A | AD3EFF2B | 0x00E47564 | file-backed | decoded |
| 0x06000116 | 548C718A | 49A7F92B | 0x00E476D8 | file-backed | decoded |
| 0x06000117 | 548C718A | .ctor | 0x00E473E8 | file-backed | decoded |
| 0x06000118 | 21A9BE87 | 819B1297 | 0x00E55198 | file-backed | decoded |
| 0x06000119 | 21A9BE87 | 3633EDAA | 0x00E551DC | file-backed | decoded |
| 0x0600011A | 21A9BE87 | .ctor | 0x00E5525C | file-backed | decoded |
| 0x0600011B | 21A9BE87 | 74028C8E | 0x00E55234 | file-backed | decoded |
| 0x0600011C | 21A9BE87 | DBB8960A | 0x00E5520C | file-backed | decoded |
| 0x0600011D | 21A9BE87 | D6135E87 | 0x00E55108 | file-backed | decoded |
| 0x0600011E | 0EA85980 | .ctor | 0x00E5B5DC | file-backed | decoded |
| 0x0600011F | 0EA85980 | D0847986 | 0x00E5B5CC | file-backed | decoded |
| 0x06000120 | 5D91D61D | E7BC8613 | 0x00E4832C | file-backed | decoded |
| 0x06000121 | 5D91D61D | .ctor | 0x00E4830C | file-backed | decoded |
| 0x06000122 | 83999CAE | 120A483B | 0x00E544B8 | file-backed | decoded |
| 0x06000123 | 83999CAE | E4B0870D | 0x00E54774 | file-backed | decoded |
| 0x06000124 | 83999CAE | 5D1CEFB9 | 0x00E54714 | file-backed | decoded |
| 0x06000125 | 83999CAE | 7EAA833A | 0x00E5433C | file-backed | decoded |
| 0x06000126 | 83999CAE | 079C1CAF | 0x00E54434 | file-backed | decoded |
| 0x06000127 | 83999CAE | 60A98D30 | 0x00E548E4 | file-backed | decoded |
| 0x06000128 | 83999CAE | 72A8122E | 0x00E54914 | file-backed | decoded |
| 0x06000129 | 83999CAE | BC3D0E0D | 0x00E5457C | file-backed | decoded |
| 0x0600012A | 83999CAE | 9DA10706 | 0x00E5467C | file-backed | decoded |
| 0x0600012B | 83999CAE | 66090B93 | 0x00E54834 | file-backed | decoded |
| 0x0600012C | 83999CAE | 5C9DC307 | 0x00E54858 | file-backed | decoded |
| 0x0600012D | 83999CAE | 9B81939A | 0x00E546CC | file-backed | decoded |
| 0x0600012E | 83999CAE | 27925635 | 0x00000000 | no RVA | unavailable |
| 0x0600012F | 83999CAE | 64174737 | 0x00E5453C | file-backed | decoded |
| 0x06000130 | 83999CAE | 8D30F30E | 0x00E54508 | file-backed | decoded |
| 0x06000131 | 83999CAE | 922F02B9 | 0x00E543A8 | file-backed | decoded |
| 0x06000132 | 83999CAE | 43AEEAA5 | 0x00E545F4 | file-backed | decoded |
| 0x06000133 | 83999CAE | 659EA81E | 0x00E545B0 | file-backed | decoded |
| 0x06000134 | 83999CAE | DD37C42C | 0x00E54800 | file-backed | decoded |
| 0x06000135 | 83999CAE | CE090AA4 | 0x00E548A0 | file-backed | decoded |
| 0x06000136 | 83999CAE | 18B87781 | 0x00E54370 | file-backed | decoded |
| 0x06000137 | 83999CAE | 4E12F716 | 0x00E5487C | file-backed | decoded |
| 0x06000138 | 83999CAE | .cctor | 0x00E5431C | file-backed | decoded |
| 0x06000139 | AC0D6684 | 1C11229E | 0x00E5BDA8 | file-backed | decoded |
| 0x0600013A | AC0D6684 | DDAEE803 | 0x00E5BD74 | file-backed | decoded |
| 0x0600013B | AC0D6684 | 798B5EB6 | 0x00E5BDDC | file-backed | decoded |
| 0x0600013C | AC0D6684 | 5F11D60F | 0x00E5BE10 | file-backed | decoded |
| 0x0600013D | AC0D6684 | .ctor | 0x00E5BD14 | file-backed | decoded |
| 0x0600013E | 3B9F519B | Invoke | 0x00000000 | no RVA | unavailable |
| 0x0600013F | 3B9F519B | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000140 | 3B9F519B | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000141 | 3B9F519B | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000142 | BFB7EF98 | 5F11D60F | 0x00E5B57C | file-backed | decoded |
| 0x06000143 | BFB7EF98 | 798B5EB6 | 0x00E5B558 | file-backed | decoded |
| 0x06000144 | BFB7EF98 | DDAEE803 | 0x00E5B3CC | file-backed | decoded |
| 0x06000145 | BFB7EF98 | 1C11229E | 0x00E5B3EC | file-backed | decoded |
| 0x06000146 | BFB7EF98 | .ctor | 0x00E5B348 | file-backed | decoded |
| 0x06000147 | 8F0BF53C | D20CC905 | 0x00E570E0 | file-backed | decoded |
| 0x06000148 | 8F0BF53C | 798B5EB6 | 0x00000000 | no RVA | unavailable |
| 0x06000149 | 8F0BF53C | 9838C122 | 0x00E56E78 | file-backed | decoded |
| 0x0600014A | 8F0BF53C | 1B80A02B | 0x00E572EC | file-backed | decoded |
| 0x0600014B | 8F0BF53C | DAB8483B | 0x00E57054 | file-backed | decoded |
| 0x0600014C | 8F0BF53C | F69CF28E | 0x00E57148 | file-backed | decoded |
| 0x0600014D | 8F0BF53C | BE8EDF2B | 0x00E56FE4 | file-backed | decoded |
| 0x0600014E | 8F0BF53C | 2683EF81 | 0x00E570A0 | file-backed | decoded |
| 0x0600014F | 8F0BF53C | 8F21799C | 0x00E57200 | file-backed | decoded |
| 0x06000150 | 8F0BF53C | 230B3CA3 | 0x00E56F9C | file-backed | decoded |
| 0x06000151 | 8F0BF53C | D0847986 | 0x00E56F54 | file-backed | decoded |
| 0x06000152 | 8F0BF53C | 61085517 | 0x00E5702C | file-backed | decoded |
| 0x06000153 | 8F0BF53C | F187C6B4 | 0x00E5700C | file-backed | decoded |
| 0x06000154 | 8F0BF53C | 958D7532 | 0x00E57074 | file-backed | decoded |
| 0x06000155 | 8F0BF53C | 9E2B0B8E | 0x00E572D0 | file-backed | decoded |
| 0x06000156 | 8F0BF53C | 970FA2B1 | 0x00E57410 | file-backed | decoded |
| 0x06000157 | 8F0BF53C | AF840B8D | 0x00E572B4 | file-backed | decoded |
| 0x06000158 | 8F0BF53C | DF8FD725 | 0x00E56F70 | file-backed | decoded |
| 0x06000159 | 8F0BF53C | C081219E | 0x00E57108 | file-backed | decoded |
| 0x0600015A | 8F0BF53C | AE814AAA | 0x00E56FC4 | file-backed | decoded |
| 0x0600015B | 8F0BF53C | 5F11D60F | 0x00000000 | no RVA | unavailable |
| 0x0600015C | 8F0BF53C | CB86DE14 | 0x00E57A10 | file-backed | decoded |
| 0x0600015D | 8F0BF53C | DC1F9B0B | 0x00E57128 | file-backed | decoded |
| 0x0600015E | 8F0BF53C | E781A32E | 0x00E57588 | file-backed | decoded |
| 0x0600015F | 8F0BF53C | .ctor | 0x00E57DD8 | file-backed | decoded |
| 0x06000160 | 8F0BF53C | C0A0A58E | 0x00E56D48 | file-backed | decoded |
| 0x06000161 | 8F0BF53C | 9F0A88B4 | 0x00E570C8 | file-backed | decoded |
| 0x06000162 | 8F0BF53C | DDAEE803 | 0x00E56F84 | file-backed | decoded |
| 0x06000163 | 8F0BF53C | 1C11229E | 0x00000000 | no RVA | unavailable |
| 0x06000164 | F714C20F | C0A0A58E | 0x00E5B708 | file-backed | decoded |
| 0x06000165 | F714C20F | DDAEE803 | 0x00E5B62C | file-backed | decoded |
| 0x06000166 | F714C20F | 9838C122 | 0x00E5B6E0 | file-backed | decoded |
| 0x06000167 | F714C20F | 5F11D60F | 0x00E5B69C | file-backed | decoded |
| 0x06000168 | F714C20F | 798B5EB6 | 0x00E5B67C | file-backed | decoded |
| 0x06000169 | F714C20F | 1C11229E | 0x00E5B654 | file-backed | decoded |
| 0x0600016A | F714C20F | .ctor | 0x00E5B600 | file-backed | decoded |
| 0x0600016B | 6F8B8C2A | 2683EF81 | 0x00E5AFD4 | file-backed | decoded |
| 0x0600016C | 6F8B8C2A | FEAD2C00 | 0x00E5B068 | file-backed | decoded |
| 0x0600016D | 6F8B8C2A | 61085517 | 0x00E5B030 | file-backed | decoded |
| 0x0600016E | 6F8B8C2A | AE814AAA | 0x00E5AF78 | file-backed | decoded |
| 0x0600016F | 6F8B8C2A | D20CC905 | 0x00E5B04C | file-backed | decoded |
| 0x06000170 | 6F8B8C2A | BE8EDF2B | 0x00E5AFB0 | file-backed | decoded |
| 0x06000171 | 6F8B8C2A | 958D7532 | 0x00E5AF8C | file-backed | decoded |
| 0x06000172 | 6F8B8C2A | 5F11D60F | 0x00E5AF14 | file-backed | decoded |
| 0x06000173 | 6F8B8C2A | 798B5EB6 | 0x00E5AEEC | file-backed | decoded |
| 0x06000174 | 6F8B8C2A | F187C6B4 | 0x00E5AFF0 | file-backed | decoded |
| 0x06000175 | 6F8B8C2A | DF8FD725 | 0x00E5AF50 | file-backed | decoded |
| 0x06000176 | 6F8B8C2A | 1C11229E | 0x00E5AEC4 | file-backed | decoded |
| 0x06000177 | 6F8B8C2A | 9F0A88B4 | 0x00E5B014 | file-backed | decoded |
| 0x06000178 | 6F8B8C2A | DDAEE803 | 0x00E5AEAC | file-backed | decoded |
| 0x06000179 | 6F8B8C2A | .ctor | 0x00E5AE5C | file-backed | decoded |
| 0x0600017A | 233BF495 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600017B | 233BF495 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600017C | 233BF495 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x0600017D | 233BF495 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x0600017E | F20229A4 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600017F | F20229A4 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000180 | F20229A4 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000181 | F20229A4 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000182 | 8E292119 | 1C11229E | 0x00E5BC78 | file-backed | decoded |
| 0x06000183 | 8E292119 | 5F11D60F | 0x00E5BCD8 | file-backed | decoded |
| 0x06000184 | 8E292119 | 798B5EB6 | 0x00E5BCAC | file-backed | decoded |
| 0x06000185 | 8E292119 | DDAEE803 | 0x00E5BC48 | file-backed | decoded |
| 0x06000186 | 8E292119 | .ctor | 0x00E5BBE8 | file-backed | decoded |
| 0x06000187 | B01B18BD | 721936BA | 0x00002514 | virtual-only | unavailable |
| 0x06000188 | 0E3E0A82 | 58B996AE | 0x00E5F424 | file-backed | decoded |
| 0x06000189 | 0E3E0A82 | 3CA44C16 | 0x00E5F3F0 | file-backed | decoded |
| 0x0600018A | 0E3E0A82 | 00B3A316 | 0x00E5F3BC | file-backed | decoded |
| 0x0600018B | 0E3E0A82 | EE228E17 | 0x00E5F39C | file-backed | decoded |
| 0x0600018C | 799BA826 | F224CB1C | 0x00E47EBC | file-backed | decoded |
| 0x0600018D | 799BA826 | .ctor | 0x00E4801C | file-backed | decoded |
| 0x0600018E | 799BA826 | 3B071C24 | 0x00E47FA4 | file-backed | decoded |
| 0x0600018F | 799BA826 | 629F9FA4 | 0x00E47E68 | file-backed | decoded |
| 0x06000190 | 799BA826 | 4D83A006 | 0x00E47EA0 | file-backed | decoded |
| 0x06000191 | 799BA826 | 9E022A33 | 0x00E47F1C | file-backed | decoded |
| 0x06000192 | 799BA826 | 24BDFDB9 | 0x00E47FE4 | file-backed | decoded |
| 0x06000193 | 799BA826 | 6AB575A1 | 0x00E47E2C | file-backed | decoded |
| 0x06000194 | 6097D7A2 | AE814AAA | 0x00E5B91C | file-backed | decoded |
| 0x06000195 | 6097D7A2 | 230B3CA3 | 0x00E5B8E0 | file-backed | decoded |
| 0x06000196 | 6097D7A2 | C081219E | 0x00E5BA74 | file-backed | decoded |
| 0x06000197 | 6097D7A2 | BE8EDF2B | 0x00E5B948 | file-backed | decoded |
| 0x06000198 | 6097D7A2 | 958D7532 | 0x00E5B9D4 | file-backed | decoded |
| 0x06000199 | 6097D7A2 | 2683EF81 | 0x00E5B9F8 | file-backed | decoded |
| 0x0600019A | 6097D7A2 | D20CC905 | 0x00E5BA50 | file-backed | decoded |
| 0x0600019B | 6097D7A2 | DDAEE803 | 0x00E5B7A4 | file-backed | decoded |
| 0x0600019C | 6097D7A2 | 9838C122 | 0x00E5B858 | file-backed | decoded |
| 0x0600019D | 6097D7A2 | F187C6B4 | 0x00E5B97C | file-backed | decoded |
| 0x0600019E | 6097D7A2 | D0847986 | 0x00E5B7C4 | file-backed | decoded |
| 0x0600019F | 6097D7A2 | C0A0A58E | 0x00E5B894 | file-backed | decoded |
| 0x060001A0 | 6097D7A2 | 798B5EB6 | 0x00E5B804 | file-backed | decoded |
| 0x060001A1 | 6097D7A2 | 1C11229E | 0x00E5B7EC | file-backed | decoded |
| 0x060001A2 | 6097D7A2 | DC1F9B0B | 0x00E5BAB0 | file-backed | decoded |
| 0x060001A3 | 6097D7A2 | 9F0A88B4 | 0x00E5BA24 | file-backed | decoded |
| 0x060001A4 | 6097D7A2 | 5F11D60F | 0x00E5B828 | file-backed | decoded |
| 0x060001A5 | 6097D7A2 | 61085517 | 0x00E5B9A8 | file-backed | decoded |
| 0x060001A6 | 6097D7A2 | .ctor | 0x00E5B754 | file-backed | decoded |
| 0x060001A7 | 72264C98 | 1C11229E | 0x00E5BB24 | file-backed | decoded |
| 0x060001A8 | 72264C98 | 798B5EB6 | 0x00E5BB50 | file-backed | decoded |
| 0x060001A9 | 72264C98 | 5F11D60F | 0x00E5BB78 | file-backed | decoded |
| 0x060001AA | 72264C98 | DDAEE803 | 0x00E5BB04 | file-backed | decoded |
| 0x060001AB | 72264C98 | .ctor | 0x00E5BAD4 | file-backed | decoded |
| 0x060001AC | AB9DE50B | .ctor | 0x003E90B6 | virtual-only | unavailable |
| 0x060001AD | AB9DE50B | 051C2B2C | 0x003E9088 | virtual-only | broken |
| 0x060001AE | AB9DE50B | 09A83A0C | 0x003E9075 | virtual-only | unavailable |
| 0x060001AF | 93BA6F05 | F69CF28E | 0x00E58A6C | file-backed | decoded |
| 0x060001B0 | 93BA6F05 | D20CC905 | 0x00E58A30 | file-backed | decoded |
| 0x060001B1 | 93BA6F05 | 8E242B0A | 0x00E590A4 | file-backed | decoded |
| 0x060001B2 | 93BA6F05 | BE8EDF2B | 0x00E58994 | file-backed | decoded |
| 0x060001B3 | 93BA6F05 | C081219E | 0x00E58A44 | file-backed | decoded |
| 0x060001B4 | 93BA6F05 | DA3EA4B1 | 0x00E58B3C | file-backed | decoded |
| 0x060001B5 | 93BA6F05 | 683A282A | 0x00E5904C | file-backed | decoded |
| 0x060001B6 | 93BA6F05 | 1C11229E | 0x00E58854 | file-backed | decoded |
| 0x060001B7 | 93BA6F05 | 8F21799C | 0x00E58ACC | file-backed | decoded |
| 0x060001B8 | 93BA6F05 | DC1F9B0B | 0x00E58A58 | file-backed | decoded |
| 0x060001B9 | 93BA6F05 | 798B5EB6 | 0x00E588A0 | file-backed | decoded |
| 0x060001BA | 93BA6F05 | 2683EF81 | 0x00E589F0 | file-backed | decoded |
| 0x060001BB | 93BA6F05 | 9B91431C | 0x00E59180 | file-backed | decoded |
| 0x060001BC | 93BA6F05 | AE814AAA | 0x00E58970 | file-backed | decoded |
| 0x060001BD | 93BA6F05 | DDAEE803 | 0x00E5883C | file-backed | decoded |
| 0x060001BE | 93BA6F05 | F187C6B4 | 0x00E589B0 | file-backed | decoded |
| 0x060001BF | 93BA6F05 | 9826AE20 | 0x00E58B84 | file-backed | decoded |
| 0x060001C0 | 93BA6F05 | 9F0A88B4 | 0x00E58A0C | file-backed | decoded |
| 0x060001C1 | 93BA6F05 | 5F11D60F | 0x00E588C0 | file-backed | decoded |
| 0x060001C2 | 93BA6F05 | 4E350D31 | 0x00E58F4C | file-backed | decoded |
| 0x060001C3 | 93BA6F05 | DAB8483B | 0x00E5892C | file-backed | decoded |
| 0x060001C4 | 93BA6F05 | 230B3CA3 | 0x00E588F0 | file-backed | decoded |
| 0x060001C5 | 93BA6F05 | 722F03A0 | 0x00E591D8 | file-backed | decoded |
| 0x060001C6 | 93BA6F05 | B5A68F16 | 0x00E593E8 | file-backed | decoded |
| 0x060001C7 | 93BA6F05 | 2BA9A426 | 0x00E59000 | file-backed | decoded |
| 0x060001C8 | 93BA6F05 | 7B923304 | 0x00E58E50 | file-backed | decoded |
| 0x060001C9 | 93BA6F05 | 61085517 | 0x00E589D4 | file-backed | decoded |
| 0x060001CA | 93BA6F05 | 958D7532 | 0x00E58954 | file-backed | decoded |
| 0x060001CB | 93BA6F05 | .ctor | 0x00E5880C | file-backed | decoded |
| 0x060001CC | 9F9B84B4 | 0A98DB0F | 0x003E67C5 | virtual-only | unavailable |
| 0x060001CD | 9F9B84B4 | F213AB2C | 0x003E65D3 | virtual-only | unavailable |
| 0x060001CE | 9F9B84B4 | 3C357BA1 | 0x003E67CD | virtual-only | unavailable |
| 0x060001CF | 9F9B84B4 | 73A67B93 | 0x003E67A8 | virtual-only | broken |
| 0x060001D0 | 9F9B84B4 | GetHashCode | 0x003E60CC | virtual-only | unavailable |
| 0x060001D1 | 9F9B84B4 | Equals | 0x003E60A8 | virtual-only | unavailable |
| 0x060001D2 | 9F9B84B4 | 41B3BE25 | 0x003E61F0 | virtual-only | unavailable |
| 0x060001D3 | 9F9B84B4 | .cctor | 0x003E67FE | virtual-only | unavailable |
| 0x060001D4 | 9F9B84B4 | 66A1A501 | 0x003E678E | virtual-only | unavailable |
| 0x060001D5 | 9F9B84B4 | 072C3593 | 0x003E65BB | virtual-only | unavailable |
| 0x060001D6 | 9F9B84B4 | DFB86EAB | 0x003E6118 | virtual-only | unavailable |
| 0x060001D7 | 9F9B84B4 | 91B2EEB4 | 0x003E6769 | virtual-only | unavailable |
| 0x060001D8 | 9F9B84B4 | E21A4DBB | 0x003E606F | virtual-only | unavailable |
| 0x060001D9 | 9F9B84B4 | .ctor | 0x003E65AB | virtual-only | unavailable |
| 0x060001DA | 9F9B84B4 | 5486A500 | 0x003E67D8 | virtual-only | unavailable |
| 0x060001DB | 9F9B84B4 | 43ABF40B | 0x003E674C | virtual-only | unavailable |
| 0x060001DC | 9F9B84B4 | 1FA2208D | 0x003E675C | virtual-only | unavailable |
| 0x060001DD | 9F9B84B4 | 2DB37708 | 0x003E673F | virtual-only | broken |
| 0x060001DE | 9F9B84B4 | B599AEA1 | 0x003E6779 | virtual-only | broken |
| 0x060001DF | 9F9B84B4 | 3E319891 | 0x003E65EB | virtual-only | unavailable |
| 0x060001E0 | 9F9B84B4 | FA0EBA01 | 0x003E6068 | virtual-only | unavailable |
| 0x060001E1 | 9F9B84B4 | 4B82353C | 0x003E664C | virtual-only | broken |
| 0x060001E2 | 9F9B84B4 | .ctor | 0x003E62FD | virtual-only | unavailable |
| 0x060001E3 | 9F9B84B4 | C62388BB | 0x003E6614 | virtual-only | unavailable |
| 0x060001E4 | 9F9B84B4 | .ctor | 0x003E6324 | virtual-only | unavailable |
| 0x060001E5 | 9F9B84B4 | C6BDC919 | 0x003E6092 | virtual-only | unavailable |
| 0x060001E6 | 9F9B84B4 | 59391295 | 0x003E6050 | virtual-only | unavailable |
| 0x060001E7 | 332F500C | .ctor | 0x0000252C | virtual-only | unavailable |
| 0x060001E8 | 332F500C | 8A9F3427 | 0x007F3C10 | virtual-only | unavailable |
| 0x060001E9 | 332F500C | 059AC82C | 0x00000000 | no RVA | unavailable |
| 0x060001EA | 332F500C | 242842B1 | 0x007F3D50 | virtual-only | broken |
| 0x060001EB | 332F500C | A6154C25 | 0x007F3D80 | virtual-only | unavailable |
| 0x060001EC | 332F500C | 46327B95 | 0x00002650 | virtual-only | unavailable |
| 0x060001ED | 332F500C | Dispose | 0x00002694 | virtual-only | unavailable |
| 0x060001EE | 332F500C | A6281F18 | 0x007F3DB4 | virtual-only | broken |
| 0x060001EF | 332F500C | 1F9BB285 | 0x0000279D | virtual-only | broken |
| 0x060001F0 | 332F500C | 883FB81F | 0x000027A8 | virtual-only | broken |
| 0x060001F1 | 332F500C | A094A48D | 0x000027EB | virtual-only | unavailable |
| 0x060001F2 | 332F500C | 8437D23F | 0x000027F5 | virtual-only | unavailable |
| 0x060001F3 | 2601F010 | BAB61EA6 | 0x00E55058 | file-backed | decoded |
| 0x060001F4 | 2601F010 | .ctor | 0x00E550CC | file-backed | decoded |
| 0x060001F5 | 2601F010 | 6BA0FC9F | 0x00E54FF0 | file-backed | decoded |
| 0x060001F6 | 2601F010 | 700814BF | 0x00E54FA0 | file-backed | decoded |
| 0x060001F7 | 2E065993 | .ctor | 0x000027FE | virtual-only | unavailable |
| 0x060001F8 | F6AFCDA3 | 1C11229E | 0x00E5B0D0 | file-backed | decoded |
| 0x060001F9 | F6AFCDA3 | E00DB38C | 0x00E5B130 | file-backed | decoded |
| 0x060001FA | F6AFCDA3 | DDAEE803 | 0x00E5B0B8 | file-backed | decoded |
| 0x060001FB | F6AFCDA3 | 5F11D60F | 0x00E5B0FC | file-backed | decoded |
| 0x060001FC | F6AFCDA3 | 798B5EB6 | 0x00E5B0E8 | file-backed | decoded |
| 0x060001FD | F6AFCDA3 | .ctor | 0x00E5B090 | file-backed | decoded |
| 0x060001FE | A4B0F598 | 841E011C | 0x00E5E348 | file-backed | decoded |
| 0x060001FF | A4B0F598 | B01C8B84 | 0x00E5E464 | file-backed | decoded |
| 0x06000200 | A4B0F598 | .ctor | 0x00E5E4A0 | file-backed | decoded |
| 0x06000201 | A4B0F598 | 15AAA512 | 0x00E5E41C | file-backed | decoded |
| 0x06000202 | A4B0F598 | A5926C85 | 0x00E5E320 | file-backed | decoded |
| 0x06000203 | A4B0F598 | CD90E311 | 0x00E5E364 | file-backed | decoded |
| 0x06000204 | A4B0F598 | DAA699AD | 0x00E5DFEC | file-backed | decoded |
| 0x06000205 | 7FA19603 | 5E2BD6A0 | 0x007F5B00 | virtual-only | broken |
| 0x06000206 | 7FA19603 | FD9A2F1D | 0x007F5BE4 | virtual-only | unavailable |
| 0x06000207 | 7FA19603 | EDB864AA | 0x007F55DC | virtual-only | unavailable |
| 0x06000208 | 7FA19603 | 80147221 | 0x007F5B6C | virtual-only | unavailable |
| 0x06000209 | 7FA19603 | 2F169B97 | 0x007F5D04 | virtual-only | unavailable |
| 0x0600020A | 7FA19603 | 67B7988A | 0x007F5868 | virtual-only | broken |
| 0x0600020B | 7FA19603 | .ctor | 0x007F5184 | virtual-only | unavailable |
| 0x0600020C | 8B0ADC86 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600020D | 8B0ADC86 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x0600020E | 8B0ADC86 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600020F | 8B0ADC86 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000210 | 3118A418 | 280671A3 | 0x00E5C9B0 | file-backed | decoded |
| 0x06000211 | 3118A418 | DC1F9B0B | 0x00E5CC1C | file-backed | decoded |
| 0x06000212 | 3118A418 | 230B3CA3 | 0x00E5CAD8 | file-backed | decoded |
| 0x06000213 | 3118A418 | 798B5EB6 | 0x00E5CA50 | file-backed | decoded |
| 0x06000214 | 3118A418 | 2683EF81 | 0x00E5CB8C | file-backed | decoded |
| 0x06000215 | 3118A418 | DDAEE803 | 0x00E5CA10 | file-backed | decoded |
| 0x06000216 | 3118A418 | D20CC905 | 0x00E5CBD4 | file-backed | decoded |
| 0x06000217 | 3118A418 | 8F21799C | 0x00E5CC68 | file-backed | decoded |
| 0x06000218 | 3118A418 | 958D7532 | 0x00E5CB6C | file-backed | decoded |
| 0x06000219 | 3118A418 | F69CF28E | 0x00E5CC3C | file-backed | decoded |
| 0x0600021A | 3118A418 | 1C11229E | 0x00E5CA28 | file-backed | decoded |
| 0x0600021B | 3118A418 | 5F11D60F | 0x00E5CA78 | file-backed | decoded |
| 0x0600021C | 3118A418 | C081219E | 0x00E5CBF4 | file-backed | decoded |
| 0x0600021D | 3118A418 | 9F0A88B4 | 0x00E5CBAC | file-backed | decoded |
| 0x0600021E | 3118A418 | 61085517 | 0x00E5CB54 | file-backed | decoded |
| 0x0600021F | 3118A418 | BE8EDF2B | 0x00E5CB14 | file-backed | decoded |
| 0x06000220 | 3118A418 | AE814AAA | 0x00E5CAFC | file-backed | decoded |
| 0x06000221 | 3118A418 | F187C6B4 | 0x00E5CB2C | file-backed | decoded |
| 0x06000222 | 3118A418 | 30AFDC81 | 0x00E5CC84 | file-backed | decoded |
| 0x06000223 | 3118A418 | .ctor | 0x00E5C930 | file-backed | decoded |
| 0x06000224 | 04826485 | BE8EDF2B | 0x00E5ABE0 | file-backed | decoded |
| 0x06000225 | 04826485 | 2683EF81 | 0x00E5ABFC | file-backed | decoded |
| 0x06000226 | 04826485 | AE814AAA | 0x00E5ABA8 | file-backed | decoded |
| 0x06000227 | 04826485 | DF8FD725 | 0x00E5AB88 | file-backed | decoded |
| 0x06000228 | 04826485 | 5F11D60F | 0x00E5AB5C | file-backed | decoded |
| 0x06000229 | 04826485 | F187C6B4 | 0x00E5AC10 | file-backed | decoded |
| 0x0600022A | 04826485 | DDAEE803 | 0x00E5AAEC | file-backed | decoded |
| 0x0600022B | 04826485 | 958D7532 | 0x00E5ABC4 | file-backed | decoded |
| 0x0600022C | 04826485 | 798B5EB6 | 0x00E5AB34 | file-backed | decoded |
| 0x0600022D | 04826485 | 1C11229E | 0x00E5AB0C | file-backed | decoded |
| 0x0600022E | 04826485 | 9F0A88B4 | 0x00E5AC34 | file-backed | decoded |
| 0x0600022F | 04826485 | .ctor | 0x00E5AAA0 | file-backed | decoded |
| 0x06000230 | 06B88B2D | 08A6F988 | 0x00E47BF0 | file-backed | decoded |
| 0x06000231 | 06B88B2D | E02E73BB | 0x00E47BD8 | file-backed | decoded |
| 0x06000232 | 5185DA87 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000233 | 5185DA87 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000234 | 5185DA87 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000235 | 5185DA87 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000236 | 3E20049A | CF992B39 | 0x00E5F330 | file-backed | decoded |
| 0x06000237 | 3E20049A | .ctor | 0x00E5F2B0 | file-backed | decoded |
| 0x06000238 | 9595A20D | 37848A9C | 0x00E484F8 | file-backed | decoded |
| 0x06000239 | 76B7C6BB | .cctor | 0x00E484D8 | file-backed | decoded |
| 0x0600023A | 76B7C6BB | 8719223C | 0x00E484A4 | file-backed | decoded |
| 0x0600023B | 76B7C6BB | 4B320188 | 0x00E48438 | file-backed | decoded |
| 0x0600023C | 76B7C6BB | 2780192C | 0x00E48414 | file-backed | decoded |
| 0x0600023D | 76B7C6BB | 201BB32D | 0x00E48480 | file-backed | decoded |
| 0x0600023E | 76B7C6BB | C3B31F98 | 0x00E48384 | file-backed | decoded |
| 0x0600023F | 76B7C6BB | 56378A2B | 0x00E483F0 | file-backed | decoded |
| 0x06000240 | 76B7C6BB | 88928EBE | 0x00E483CC | file-backed | decoded |
| 0x06000241 | 76B7C6BB | F335EF16 | 0x00E4845C | file-backed | decoded |
| 0x06000242 | 76B7C6BB | 08886D9D | 0x00E483A8 | file-backed | decoded |
| 0x06000243 | 76B7C6BB | DF063B01 | 0x00E48360 | file-backed | decoded |
| 0x06000244 | 931A4504 | .ctor | 0x00E57E20 | file-backed | decoded |
| 0x06000245 | 931A4504 | DF8FD725 | 0x00E57E0C | file-backed | decoded |
| 0x06000246 | 4703A71E | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000247 | 4703A71E | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000248 | 4703A71E | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000249 | 4703A71E | .ctor | 0x00000000 | no RVA | unavailable |
| 0x0600024A | 2AB62490 | A31E4F27 | 0x00E5F244 | file-backed | decoded |
| 0x0600024B | 2AB62490 | .ctor | 0x00E5F1D4 | file-backed | decoded |
| 0x0600024C | 9C11B202 | 08A47435 | 0x00002808 | virtual-only | unavailable |
| 0x0600024D | 9C11B202 | A60AB602 | 0x00002930 | virtual-only | broken |
| 0x0600024E | 9C11B202 | .ctor | 0x00002947 | virtual-only | unavailable |
| 0x0600024F | 9C11B202 | Equals | 0x00002954 | virtual-only | broken |
| 0x06000250 | 9C11B202 | GetHashCode | 0x00002974 | virtual-only | broken |
| 0x06000251 | 9C11B202 | 192243B6 | 0x0000298C | virtual-only | unavailable |
| 0x06000252 | 9C11B202 | ToString | 0x000029A8 | virtual-only | unavailable |
| 0x06000253 | 9C11B202 | 92A7A51C | 0x000029C0 | virtual-only | unavailable |
| 0x06000254 | 9C11B202 | EA0EEE1A | 0x000029DB | virtual-only | broken |
| 0x06000255 | 9DBB03A4 | Dispose | 0x00E56484 | file-backed | decoded |
| 0x06000256 | 9DBB03A4 | .ctor | 0x00E56588 | file-backed | decoded |
| 0x06000257 | 9DBB03A4 | 7EA9923C | 0x00E56420 | file-backed | decoded |
| 0x06000258 | B5BF2612 | F187C6B4 | 0x00E5ADFC | file-backed | decoded |
| 0x06000259 | B5BF2612 | 958D7532 | 0x00E5AD98 | file-backed | decoded |
| 0x0600025A | B5BF2612 | 5F11D60F | 0x00E5ACFC | file-backed | decoded |
| 0x0600025B | B5BF2612 | DDAEE803 | 0x00E5AC8C | file-backed | decoded |
| 0x0600025C | B5BF2612 | AE814AAA | 0x00E5AD6C | file-backed | decoded |
| 0x0600025D | B5BF2612 | 1C11229E | 0x00E5ACB4 | file-backed | decoded |
| 0x0600025E | B5BF2612 | 2683EF81 | 0x00E5ADD8 | file-backed | decoded |
| 0x0600025F | B5BF2612 | DF8FD725 | 0x00E5AD44 | file-backed | decoded |
| 0x06000260 | B5BF2612 | BE8EDF2B | 0x00E5ADBC | file-backed | decoded |
| 0x06000261 | B5BF2612 | 798B5EB6 | 0x00E5ACD4 | file-backed | decoded |
| 0x06000262 | B5BF2612 | 9F0A88B4 | 0x00E5AE20 | file-backed | decoded |
| 0x06000263 | B5BF2612 | 258224BC | 0x00E5AE34 | file-backed | decoded |
| 0x06000264 | B5BF2612 | .ctor | 0x00E5AC48 | file-backed | decoded |
| 0x06000265 | 22864383 | AD3AA131 | 0x00E5DCC0 | file-backed | decoded |
| 0x06000266 | 22864383 | A5AD2490 | 0x00E5DDF0 | file-backed | decoded |
| 0x06000267 | 22864383 | 891D4187 | 0x00E5DE34 | file-backed | decoded |
| 0x06000268 | 22864383 | 0C17F91A | 0x00E5DCDC | file-backed | decoded |
| 0x06000269 | 22864383 | 8D360226 | 0x00E5DCF8 | file-backed | decoded |
| 0x0600026A | 22864383 | .ctor | 0x00E5DC54 | file-backed | decoded |
| 0x0600026B | EC0E7286 | DF8FD725 | 0x00E5A9E8 | file-backed | decoded |
| 0x0600026C | EC0E7286 | DDAEE803 | 0x00E5A954 | file-backed | decoded |
| 0x0600026D | EC0E7286 | 2683EF81 | 0x00E5AA4C | file-backed | decoded |
| 0x0600026E | EC0E7286 | F187C6B4 | 0x00E5AA68 | file-backed | decoded |
| 0x0600026F | EC0E7286 | BE8EDF2B | 0x00E5AA38 | file-backed | decoded |
| 0x06000270 | EC0E7286 | 9F0A88B4 | 0x00E5AA84 | file-backed | decoded |
| 0x06000271 | EC0E7286 | 5F11D60F | 0x00E5A9B4 | file-backed | decoded |
| 0x06000272 | EC0E7286 | 958D7532 | 0x00E5AA24 | file-backed | decoded |
| 0x06000273 | EC0E7286 | 798B5EB6 | 0x00E5A98C | file-backed | decoded |
| 0x06000274 | EC0E7286 | AE814AAA | 0x00E5AA08 | file-backed | decoded |
| 0x06000275 | EC0E7286 | 1C11229E | 0x00E5A96C | file-backed | decoded |
| 0x06000276 | EC0E7286 | .ctor | 0x00E5A90C | file-backed | decoded |
| 0x06000277 | A924C101 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000278 | A924C101 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000279 | A924C101 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600027A | A924C101 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x0600027B | 6633B699 | 7026BDB3 | 0x00E4FE20 | file-backed | decoded |
| 0x0600027C | 6633B699 | DF3D6327 | 0x00E4FF20 | file-backed | decoded |
| 0x0600027D | 6633B699 | FBA6060E | 0x00E4E070 | file-backed | decoded |
| 0x0600027E | 6633B699 | 4435311D | 0x00E4EE54 | file-backed | decoded |
| 0x0600027F | 6633B699 | 6BBB0B8D | 0x00E52E74 | file-backed | decoded |
| 0x06000280 | 6633B699 | B1A9FC34 | 0x00E4E7A8 | file-backed | decoded |
| 0x06000281 | 6633B699 | 3300F60E | 0x00E4D068 | file-backed | decoded |
| 0x06000282 | 6633B699 | 800AB499 | 0x00E531C0 | file-backed | decoded |
| 0x06000283 | 6633B699 | 3BAD442A | 0x00E53B8C | file-backed | decoded |
| 0x06000284 | 6633B699 | 3C806315 | 0x00E539C0 | file-backed | decoded |
| 0x06000285 | 6633B699 | 4935572B | 0x00E5366C | file-backed | decoded |
| 0x06000286 | 6633B699 | 1A100412 | 0x00E53F54 | file-backed | decoded |
| 0x06000287 | 6633B699 | FC0F1D31 | 0x00E4F578 | file-backed | decoded |
| 0x06000288 | 6633B699 | 05B08081 | 0x00E4EA40 | file-backed | decoded |
| 0x06000289 | 6633B699 | 7106D89C | 0x00E53E48 | file-backed | decoded |
| 0x0600028A | 6633B699 | 549EC905 | 0x00E4F400 | file-backed | decoded |
| 0x0600028B | 6633B699 | 85040E1F | 0x00E4FB14 | file-backed | decoded |
| 0x0600028C | 6633B699 | 1B9A0FA8 | 0x00E4DF70 | file-backed | decoded |
| 0x0600028D | 6633B699 | B6378BA4 | 0x00E4D20C | file-backed | decoded |
| 0x0600028E | 6633B699 | 1C922035 | 0x00E4F170 | file-backed | decoded |
| 0x0600028F | 6633B699 | A70C929E | 0x00E4E82C | file-backed | decoded |
| 0x06000290 | 6633B699 | 5931DC83 | 0x00E4F444 | file-backed | decoded |
| 0x06000291 | 6633B699 | 3F172326 | 0x00E4E950 | file-backed | decoded |
| 0x06000292 | 6633B699 | 478FD68B | 0x00E4E5F8 | file-backed | decoded |
| 0x06000293 | 6633B699 | 6D996612 | 0x00E4F51C | file-backed | decoded |
| 0x06000294 | 6633B699 | A12F070C | 0x00E4EBD0 | file-backed | decoded |
| 0x06000295 | 6633B699 | 8B1A351C | 0x00E4E4FC | file-backed | decoded |
| 0x06000296 | 6633B699 | D719AC25 | 0x00E4FE8C | file-backed | decoded |
| 0x06000297 | 6633B699 | 5D26C703 | 0x00E52B28 | file-backed | decoded |
| 0x06000298 | 6633B699 | 21803F9F | 0x00E4FAC8 | file-backed | decoded |
| 0x06000299 | 6633B699 | B539783E | 0x00E4D3A0 | file-backed | decoded |
| 0x0600029A | 6633B699 | 3526928B | 0x00E4FC50 | file-backed | decoded |
| 0x0600029B | 6633B699 | B51FB5B5 | 0x00E4EC68 | file-backed | decoded |
| 0x0600029C | 6633B699 | 918908BF | 0x00E5205C | file-backed | decoded |
| 0x0600029D | 6633B699 | B1190689 | 0x00E4DEBC | file-backed | decoded |
| 0x0600029E | 6633B699 | 7603EE86 | 0x00E4EFD8 | file-backed | decoded |
| 0x0600029F | 6633B699 | AF093527 | 0x00E4E45C | file-backed | decoded |
| 0x060002A0 | 6633B699 | 7326F70C | 0x00E517E4 | file-backed | decoded |
| 0x060002A1 | 6633B699 | 8C379AB2 | 0x00E4F7DC | file-backed | decoded |
| 0x060002A2 | 6633B699 | 99BED52B | 0x00E4FB94 | file-backed | decoded |
| 0x060002A3 | 6633B699 | BD3588B7 | 0x00E4DE6C | file-backed | decoded |
| 0x060002A4 | 6633B699 | 513EF216 | 0x00E5325C | file-backed | decoded |
| 0x060002A5 | 6633B699 | AFA5D200 | 0x00E52CA4 | file-backed | decoded |
| 0x060002A6 | 6633B699 | C7154D83 | 0x00E4F068 | file-backed | decoded |
| 0x060002A7 | 6633B699 | CD3F76B2 | 0x00E4E580 | file-backed | decoded |
| 0x060002A8 | 6633B699 | 019272A0 | 0x00E4DF18 | file-backed | decoded |
| 0x060002A9 | 6633B699 | 1C856C10 | 0x00E4F940 | file-backed | decoded |
| 0x060002AA | 6633B699 | 91AF9321 | 0x00E4E200 | file-backed | decoded |
| 0x060002AB | 6633B699 | 858D880A | 0x00E4D310 | file-backed | decoded |
| 0x060002AC | 6633B699 | E41CC286 | 0x00E4CC90 | file-backed | decoded |
| 0x060002AD | 6633B699 | AF908ABB | 0x00E4E174 | file-backed | decoded |
| 0x060002AE | 6633B699 | 35A1509D | 0x00E4F8B4 | file-backed | decoded |
| 0x060002AF | 6633B699 | 879D4733 | 0x00E529C0 | file-backed | decoded |
| 0x060002B0 | 6633B699 | 22B83F93 | 0x00E4FFA4 | file-backed | decoded |
| 0x060002B1 | 6633B699 | 5EA8F02F | 0x00E53CAC | file-backed | decoded |
| 0x060002B2 | 6633B699 | D9B2E438 | 0x00E53A10 | file-backed | decoded |
| 0x060002B3 | 6633B699 | AE967FAB | 0x00E4E3F0 | file-backed | decoded |
| 0x060002B4 | 6633B699 | EF8B98AF | 0x00E4D280 | file-backed | decoded |
| 0x060002B5 | 6633B699 | 79AF42A2 | 0x00E52DD0 | file-backed | decoded |
| 0x060002B6 | 6633B699 | CEB29D2C | 0x00E4EB24 | file-backed | decoded |
| 0x060002B7 | 6633B699 | 4F2680A8 | 0x00E4E9B4 | file-backed | decoded |
| 0x060002B8 | 6633B699 | C9BF0D8B | 0x00E53B08 | file-backed | decoded |
| 0x060002B9 | 6633B699 | EB2248B9 | 0x00E4EEB4 | file-backed | decoded |
| 0x060002BA | 6633B699 | CE8DFD9B | 0x00E4D590 | file-backed | decoded |
| 0x060002BB | 6633B699 | 792359AC | 0x00E4E0EC | file-backed | decoded |
| 0x060002BC | 6633B699 | B839B220 | 0x00E52BB4 | file-backed | decoded |
| 0x060002BD | 6633B699 | 76862C12 | 0x00E4DB64 | file-backed | decoded |
| 0x060002BE | 6633B699 | 3EB2FA2F | 0x00E4F318 | file-backed | decoded |
| 0x060002BF | 6633B699 | 34B71D07 | 0x00E52D44 | file-backed | decoded |
| 0x060002C0 | 6633B699 | 8C26AAA4 | 0x00E5361C | file-backed | decoded |
| 0x060002C1 | 6633B699 | FA13B832 | 0x00E54034 | file-backed | decoded |
| 0x060002C2 | 6633B699 | 6CB9379B | 0x00E4DDC0 | file-backed | decoded |
| 0x060002C3 | 6633B699 | C5931FB9 | 0x00E52FE4 | file-backed | decoded |
| 0x060002C4 | 6633B699 | 21026DA1 | 0x00E4ED90 | file-backed | decoded |
| 0x060002C5 | 6633B699 | AE2F9A26 | 0x00E4DE14 | file-backed | decoded |
| 0x060002C6 | 6633B699 | D1934D8B | 0x00E4E250 | file-backed | decoded |
| 0x060002C7 | 6633B699 | E82B3785 | 0x00E4CBA8 | file-backed | decoded |
| 0x060002C8 | 6633B699 | 9DB004B4 | 0x00E53EA4 | file-backed | decoded |
| 0x060002C9 | 6633B699 | 64A9A13F | 0x00E4F208 | file-backed | decoded |
| 0x060002CA | 6633B699 | 50080737 | 0x00E4EAAC | file-backed | decoded |
| 0x060002CB | 6633B699 | 14B8FDA4 | 0x00E5310C | file-backed | decoded |
| 0x060002CC | 6633B699 | B0964A39 | 0x00E4F360 | file-backed | decoded |
| 0x060002CD | 6633B699 | C983FEBF | 0x00E4E704 | file-backed | decoded |
| 0x060002CE | 6633B699 | 74B39F1C | 0x00E52594 | file-backed | decoded |
| 0x060002CF | 6633B699 | BA870B21 | 0x00E53ED4 | file-backed | decoded |
| 0x060002D0 | 6633B699 | D3052B17 | 0x00E4ECF8 | file-backed | decoded |
| 0x060002D1 | 6633B699 | A302862D | 0x00E4F2C0 | file-backed | decoded |
| 0x060002D2 | 6633B699 | B59103A5 | 0x00E52C2C | file-backed | decoded |
| 0x060002D3 | 6633B699 | 86043CA7 | 0x00E4F1DC | file-backed | decoded |
| 0x060002D4 | 6633B699 | 89A2E63B | 0x00E4E354 | file-backed | decoded |
| 0x060002D5 | 6633B699 | 1101EC8C | 0x00E53F80 | file-backed | decoded |
| 0x060002D6 | 6633B699 | B40B1435 | 0x00E4DD64 | file-backed | decoded |
| 0x060002D7 | 6633B699 | 9C1EF127 | 0x00E4F0FC | file-backed | decoded |
| 0x060002D8 | 6633B699 | A1A14C36 | 0x00E4E2AC | file-backed | decoded |
| 0x060002D9 | 6633B699 | CD970A3D | 0x00E4F270 | file-backed | decoded |
| 0x060002DA | 6633B699 | 7A15E31B | 0x00E4EF40 | file-backed | decoded |
| 0x060002DB | 6633B699 | DBA84833 | 0x00E4DFE4 | file-backed | decoded |
| 0x060002DC | 6633B699 | 71BAFF88 | 0x00E4F3A0 | file-backed | decoded |
| 0x060002DD | 6633B699 | 6D36168F | 0x00E52AA0 | file-backed | decoded |
| 0x060002DE | 6633B699 | BC0FF3AE | 0x00E4EE18 | file-backed | decoded |
| 0x060002DF | 6633B699 | 1D3F64BC | 0x00E4E8BC | file-backed | decoded |
| 0x060002E0 | 6633B699 | .cctor | 0x00E542C8 | file-backed | decoded |
| 0x060002E1 | 6633B699 | 1CB8B58E | 0x00E4E69C | file-backed | decoded |
| 0x060002E2 | 6633B699 | 9D21EEA9 | 0x00E4F4B0 | file-backed | decoded |
| 0x060002E3 | 6633B699 | .ctor | 0x00E4877C | file-backed | decoded |
| 0x060002E4 | ADA24B34 | 192B7C14 | 0x00E55620 | file-backed | decoded |
| 0x060002E5 | ADA24B34 | 7484AA34 | 0x00E552F0 | file-backed | decoded |
| 0x060002E6 | ADA24B34 | CD3E751A | 0x00E55294 | file-backed | decoded |
| 0x060002E7 | ADA24B34 | .ctor | 0x00E55278 | file-backed | decoded |
| 0x060002E8 | 5BBB3B3F | .ctor | 0x007F5E60 | virtual-only | unavailable |
| 0x060002E9 | 5BBB3B3F | .ctor | 0x007F5E34 | virtual-only | unavailable |
| 0x060002EA | 40AB99A9 | FB2BD50C | 0x00E54C68 | file-backed | decoded |
| 0x060002EB | 40AB99A9 | 14B13C9A | 0x00E54C7C | file-backed | decoded |
| 0x060002EC | 40AB99A9 | .cctor | 0x00E54944 | file-backed | decoded |
| 0x060002ED | 6B8D4FA4 | 8FB88FA4 | 0x007F4EBC | virtual-only | unavailable |
| 0x060002EE | 6B8D4FA4 | 70B2D4B7 | 0x007F4E2C | virtual-only | unavailable |
| 0x060002EF | 6B8D4FA4 | 63A2B889 | 0x007F4F4C | virtual-only | unavailable |
| 0x060002F0 | 6B8D4FA4 | .cctor | 0x007F4FF8 | virtual-only | unavailable |
| 0x060002F1 | 6B8D4FA4 | FC052207 | 0x007F4FAC | virtual-only | unavailable |
| 0x060002F2 | 6B8D4FA4 | 0F887B3C | 0x007F4D70 | virtual-only | unavailable |
| 0x060002F3 | 6B8D4FA4 | 448CB93A | 0x007F3EAC | virtual-only | unavailable |
| 0x060002F4 | 6B8D4FA4 | 940EDE90 | 0x007F4D4C | virtual-only | unavailable |
| 0x060002F5 | 6B8D4FA4 | BFA742A0 | 0x007F4F1C | virtual-only | broken |
| 0x060002F6 | 6B8D4FA4 | .ctor | 0x007F4FCC | virtual-only | unavailable |
| 0x060002F7 | 6B8D4FA4 | 7486A908 | 0x007F4DFC | virtual-only | broken |
| 0x060002F8 | 6B8D4FA4 | F631913C | 0x007F4E5C | virtual-only | unavailable |
| 0x060002F9 | 6B8D4FA4 | 7FAFF03B | 0x007F4F80 | virtual-only | unavailable |
| 0x060002FA | 6B8D4FA4 | 341C8983 | 0x007F4EEC | virtual-only | unavailable |
| 0x060002FB | 6B8D4FA4 | D1966DBB | 0x007F4DCC | virtual-only | unavailable |
| 0x060002FC | 6B8D4FA4 | 5E305933 | 0x007F4E8C | virtual-only | broken |
| 0x060002FD | 6B8D4FA4 | D3BC55AF | 0x007F4D28 | virtual-only | unavailable |
| 0x060002FE | 6B8D4FA4 | DFBCC687 | 0x007F3E78 | virtual-only | unavailable |
| 0x060002FF | E0234509 | 199F8D92 | 0x00E59FA0 | file-backed | decoded |
| 0x06000300 | E0234509 | AE814AAA | 0x00E59B38 | file-backed | decoded |
| 0x06000301 | E0234509 | CA24F909 | 0x00E59E78 | file-backed | decoded |
| 0x06000302 | E0234509 | F187C6B4 | 0x00E59B80 | file-backed | decoded |
| 0x06000303 | E0234509 | 798C2037 | 0x00E59DA0 | file-backed | decoded |
| 0x06000304 | E0234509 | F69CF28E | 0x00E59C94 | file-backed | decoded |
| 0x06000305 | E0234509 | 20B03580 | 0x00E5A274 | file-backed | decoded |
| 0x06000306 | E0234509 | 8F21799C | 0x00E59D14 | file-backed | decoded |
| 0x06000307 | E0234509 | 2683EF81 | 0x00E59BF0 | file-backed | decoded |
| 0x06000308 | E0234509 | B9029922 | 0x00E5A1C4 | file-backed | decoded |
| 0x06000309 | E0234509 | C7B114A9 | 0x00E59EA8 | file-backed | decoded |
| 0x0600030A | E0234509 | 61085517 | 0x00E59B94 | file-backed | decoded |
| 0x0600030B | E0234509 | C5A477B5 | 0x00E59DE0 | file-backed | decoded |
| 0x0600030C | E0234509 | DC1F9B0B | 0x00E59C70 | file-backed | decoded |
| 0x0600030D | E0234509 | 1C11229E | 0x00E59A80 | file-backed | decoded |
| 0x0600030E | E0234509 | BE8EDF2B | 0x00E59B54 | file-backed | decoded |
| 0x0600030F | E0234509 | 798B5EB6 | 0x00E59AA8 | file-backed | decoded |
| 0x06000310 | E0234509 | C081219E | 0x00E59C54 | file-backed | decoded |
| 0x06000311 | E0234509 | 5F8E988B | 0x00E59E40 | file-backed | decoded |
| 0x06000312 | E0234509 | 230B3CA3 | 0x00E59B08 | file-backed | decoded |
| 0x06000313 | E0234509 | 958D7532 | 0x00E59BD4 | file-backed | decoded |
| 0x06000314 | E0234509 | 5F11D60F | 0x00E59AC8 | file-backed | decoded |
| 0x06000315 | E0234509 | 1896E008 | 0x00E59E08 | file-backed | decoded |
| 0x06000316 | E0234509 | DDAEE803 | 0x00E59A58 | file-backed | decoded |
| 0x06000317 | E0234509 | DAB8483B | 0x00E59BB8 | file-backed | decoded |
| 0x06000318 | E0234509 | D20CC905 | 0x00E59C38 | file-backed | decoded |
| 0x06000319 | E0234509 | 9F0A88B4 | 0x00E59C1C | file-backed | decoded |
| 0x0600031A | E0234509 | .ctor | 0x00E59A0C | file-backed | decoded |
| 0x0600031B | 962003A5 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600031C | 962003A5 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600031D | 962003A5 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x0600031E | 962003A5 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x0600031F | 7E33331F | 850D9B94 | 0x00E55F90 | file-backed | decoded |
| 0x06000320 | 7E33331F | FC308704 | 0x00E55ED4 | file-backed | decoded |
| 0x06000321 | 7E33331F | 20BE0700 | 0x00E55EC0 | file-backed | decoded |
| 0x06000322 | 7E33331F | 6B20BB9E | 0x00E5605C | file-backed | decoded |
| 0x06000323 | 7E33331F | .ctor | 0x00E56040 | file-backed | decoded |
| 0x06000324 | 7E33331F | 58AA312E | 0x00E55E98 | file-backed | decoded |
| 0x06000325 | B70C980B | 5F11D60F | 0x00E5A6C4 | file-backed | decoded |
| 0x06000326 | B70C980B | DF8FD725 | 0x00E5A700 | file-backed | decoded |
| 0x06000327 | B70C980B | 1C11229E | 0x00E5A674 | file-backed | decoded |
| 0x06000328 | B70C980B | DDAEE803 | 0x00E5A654 | file-backed | decoded |
| 0x06000329 | B70C980B | 798B5EB6 | 0x00E5A69C | file-backed | decoded |
| 0x0600032A | B70C980B | F187C6B4 | 0x00E5A720 | file-backed | decoded |
| 0x0600032B | B70C980B | .ctor | 0x00E5A614 | file-backed | decoded |
| 0x0600032C | 6F08D20D | 95A99086 | 0x003E6CE8 | virtual-only | broken |
| 0x0600032D | 6F08D20D | 24B254BA | 0x003E6A5C | virtual-only | unavailable |
| 0x0600032E | 6F08D20D | 00272702 | 0x003E6BD0 | virtual-only | unavailable |
| 0x0600032F | 6F08D20D | .ctor | 0x003E687C | virtual-only | broken |
| 0x06000330 | 6F08D20D | 7F9E2BAC | 0x003E6FCC | virtual-only | broken |
| 0x06000331 | 6F08D20D | 463E1884 | 0x003E6934 | virtual-only | broken |
| 0x06000332 | 6F08D20D | 378EA88F | 0x003E6F38 | virtual-only | unavailable |
| 0x06000333 | 6F08D20D | 7EAB00A9 | 0x003E6AA1 | virtual-only | unavailable |
| 0x06000334 | 6F08D20D | 6299D281 | 0x003E7294 | virtual-only | unavailable |
| 0x06000335 | 6F08D20D | 3A8D25BE | 0x003E6B33 | virtual-only | unavailable |
| 0x06000336 | 6F08D20D | 6F3ABC0F | 0x003E6B04 | virtual-only | unavailable |
| 0x06000337 | 6F08D20D | 29264628 | 0x003E6CA0 | virtual-only | unavailable |
| 0x06000338 | 6F08D20D | D51FA030 | 0x003E6AAC | virtual-only | unavailable |
| 0x06000339 | 6F08D20D | .ctor | 0x003E6845 | virtual-only | unavailable |
| 0x0600033A | 6F08D20D | 59297FA1 | 0x003E6D6C | virtual-only | broken |
| 0x0600033B | 6F08D20D | 6A8019AD | 0x003E6A4B | virtual-only | unavailable |
| 0x0600033C | 6F08D20D | 1B135A18 | 0x003E72B4 | virtual-only | unavailable |
| 0x0600033D | 6F08D20D | 53057F0C | 0x003E72D4 | virtual-only | unavailable |
| 0x0600033E | 6F08D20D | 83A4F125 | 0x003E6B70 | virtual-only | unavailable |
| 0x0600033F | 6F08D20D | 93AF5D8E | 0x003E6F88 | virtual-only | unavailable |
| 0x06000340 | 6F08D20D | 8BBC3F2C | 0x003E6914 | virtual-only | unavailable |
| 0x06000341 | 6F08D20D | 433E0E97 | 0x003E6DF0 | virtual-only | unavailable |
| 0x06000342 | 6F08D20D | D5238613 | 0x003E683A | virtual-only | unavailable |
| 0x06000343 | 3A182F39 | .ctor | 0x007F5E90 | virtual-only | broken |
| 0x06000344 | E38F891F | .ctor | 0x003E7F98 | virtual-only | unavailable |
| 0x06000345 | 49B812B6 | Equals | 0x00002A08 | virtual-only | broken |
| 0x06000346 | 49B812B6 | GetHashCode | 0x00002A28 | virtual-only | broken |
| 0x06000347 | 49B812B6 | E7AA632B | 0x00002A40 | virtual-only | broken |
| 0x06000348 | 49B812B6 | ToString | 0x00002A5C | virtual-only | unavailable |
| 0x06000349 | 49B812B6 | 5818E199 | 0x00002A74 | virtual-only | unavailable |
| 0x0600034A | 49B812B6 | 3E8DDF8A | 0x00002A9D | virtual-only | unavailable |
| 0x0600034B | 49B812B6 | .ctor | 0x00002AA7 | virtual-only | broken |
| 0x0600034C | F382C8BA | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600034D | F382C8BA | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x0600034E | F382C8BA | Invoke | 0x00000000 | no RVA | unavailable |
| 0x0600034F | F382C8BA | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000350 | 77103C82 | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000351 | 77103C82 | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000352 | 77103C82 | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000353 | 77103C82 | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000354 | 5A9C77AF | Invoke | 0x00000000 | no RVA | unavailable |
| 0x06000355 | 5A9C77AF | EndInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000356 | 5A9C77AF | BeginInvoke | 0x00000000 | no RVA | unavailable |
| 0x06000357 | 5A9C77AF | .ctor | 0x00000000 | no RVA | unavailable |
| 0x06000358 | 7FB60882 | .ctor | 0x00E473D4 | file-backed | decoded |
| 0x06000359 | 7FB60882 | 0A11DB2C | 0x00E473B8 | file-backed | decoded |
| 0x0600035A | ABA5F297 | F187C6B4 | 0x00E57F94 | file-backed | decoded |
| 0x0600035B | ABA5F297 | 35A9DE13 | 0x00E5813C | file-backed | decoded |
| 0x0600035C | ABA5F297 | DC1F9B0B | 0x00E5808C | file-backed | decoded |
| 0x0600035D | ABA5F297 | 61085517 | 0x00E57FB0 | file-backed | decoded |
| 0x0600035E | ABA5F297 | AE814AAA | 0x00E57F4C | file-backed | decoded |
| 0x0600035F | ABA5F297 | E236CDB4 | 0x00E58394 | file-backed | decoded |
| 0x06000360 | ABA5F297 | 2683EF81 | 0x00E5800C | file-backed | decoded |
| 0x06000361 | ABA5F297 | 8608E7A7 | 0x00E585B4 | file-backed | decoded |
| 0x06000362 | ABA5F297 | DDAEE803 | 0x00E57E78 | file-backed | decoded |
| 0x06000363 | ABA5F297 | 8F21799C | 0x00E580E4 | file-backed | decoded |
| 0x06000364 | ABA5F297 | C081219E | 0x00E58068 | file-backed | decoded |
| 0x06000365 | ABA5F297 | 1C11229E | 0x00E57E98 | file-backed | decoded |
| 0x06000366 | ABA5F297 | 798B5EB6 | 0x00E57ECC | file-backed | decoded |
| 0x06000367 | ABA5F297 | C08B3492 | 0x00E58470 | file-backed | decoded |
| 0x06000368 | ABA5F297 | 25B0AF34 | 0x00E5810C | file-backed | decoded |
| 0x06000369 | ABA5F297 | F69CF28E | 0x00E580B0 | file-backed | decoded |
| 0x0600036A | ABA5F297 | 9F0A88B4 | 0x00E58030 | file-backed | decoded |
| 0x0600036B | ABA5F297 | 230B3CA3 | 0x00E57F20 | file-backed | decoded |
| 0x0600036C | ABA5F297 | 958D7532 | 0x00E57FE8 | file-backed | decoded |
| 0x0600036D | ABA5F297 | D20CC905 | 0x00E58054 | file-backed | decoded |
| 0x0600036E | ABA5F297 | FA011726 | 0x00E587E4 | file-backed | decoded |
| 0x0600036F | ABA5F297 | 5537012A | 0x00E58434 | file-backed | decoded |
| 0x06000370 | ABA5F297 | 5F11D60F | 0x00E57EEC | file-backed | decoded |
| 0x06000371 | ABA5F297 | B38CB59C | 0x00E5860C | file-backed | decoded |
| 0x06000372 | ABA5F297 | B722B53C | 0x00E584C0 | file-backed | decoded |
| 0x06000373 | ABA5F297 | 6620B59C | 0x00E582E0 | file-backed | decoded |
| 0x06000374 | ABA5F297 | DAB8483B | 0x00E57FCC | file-backed | decoded |
| 0x06000375 | ABA5F297 | BE8EDF2B | 0x00E57F78 | file-backed | decoded |
| 0x06000376 | ABA5F297 | .ctor | 0x00E57E48 | file-backed | decoded |
| 0x06000377 | E49A2C03 | 1A341933 | 0x00002AB4 | virtual-only | unavailable |
| 0x06000378 | E49A2C03 | .ctor | 0x00002AE6 | virtual-only | unavailable |

</details>

## Reproduction and provenance
`scripts/analyze_vm_constructor.py`, `scripts/recover_vm_nested_locals.py` and `scripts/verify_reader_jump.py` emulate selected offline instructions and may include sample-specific assumptions. They do **not** execute the suspicious EXE. The raw recovered IL and CSV/JSON inventories are the primary evidence; helper classifications and speculative paths should not override them.

## Unresolved
The precise runtime contents of the 52-element `76B7C6BB.D0244F83` array (including element 5), subsequent bytecode-reader jumps, 163 virtual-only bodies, actual licensing endpoints contacted, and any application-level gameplay functionality were not recovered. No verified aimbot/ESP pipeline, anticheat bypass, exfiltration, persistence, or remote-control path can be asserted.
