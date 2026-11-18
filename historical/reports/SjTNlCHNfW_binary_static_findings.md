# Static inspection — SjTNlCHNfW.exe

## Provenance
- File: `SjTNlCHNfW(1).exe`
- Size: 6,783,488 bytes
- SHA-256: `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`
- Method: byte/PE structure inspection, searches of raw readable strings, and reference to prior static IL recovery of the identical hash. The executable was never executed.

## PE section layout

| Section | Virtual address | Virtual size | File-backed bytes | Entropy (bits/byte) |
|---|---:|---:|---:|---:|
| `F!_~Pyan` | `0x00002000` | 4,073,164 | **0** | n/a |
| `0[n6P0.A` | `0x003E6000` | 4,259,515 | **0** | n/a |
| `OVgPD_NR` | `0x007F6000` | 8 | 512 | 0.061 |
| `_kh!cr6M` | `0x007F8000` | 6,777,544 | 6,777,856 | 7.997 |
| `PF.CT8VA` | `0x00E70000` | 3,499 | 3,584 | 5.079 |
| `:zqS2t{G` | `0x00E72000` | 12 | 512 | 0.102 |

## Confirmed static findings
- Windows PE32 (Intel i386) CLR/.NET executable.
- The sections at RVA `0x2000` and `0x3E6000` have no file-backed bytes. The managed entry point MethodDef token `0x06000023` lies in the first one, at RVA `0x2050`; its original IL cannot be recovered directly from that file location.
- Static metadata inventory of the same SHA-256 contains 888 MethodDef rows. Earlier disassembly found 650 file-backed IL bodies and 163 method RVAs in virtual-only sections; 75 have no body RVA.
- `<Module>::.cctor` has a file-backed body that constructs `6633B699` and calls `6633B699.FA13B832`, the custom VM dispatcher. The VM constructor registers 256 opcode keys to delegate handlers; numerous handlers are shared.
- Raw UTF-16LE strings expose a licensing/activation pattern: `activation.php?code=`, `type=activation&code=`, `&hwid=`, `&hash=`, `deactivation.php?hash=`, `type=deactivation&hash=`.
- Raw metadata strings show `WebClient`, `DownloadString`, `shell32.dll`, `kernel32`, and `ServerDownloadResult`; these are API references, not independently confirmed behavioral execution.
- A readable warning states `This code requires valid serial number to run.`
- No clear, non-Microsoft network endpoint was located using basic ASCII/UTF-16 URL/IP searches. Obfuscation can conceal endpoints.

## Assessment
- The artifact demonstrates strong .NET virtualizing/packing behavior, including virtual-only IL method addresses and a high-entropy file-backed section.
- Licensing/activation is supported by readable strings; direct persistence, data theft, remote command execution, and exfiltration are **not established** by this inspection.
- Exact application startup behavior remains unknown because the entry-point method body is not stored at its declared RVA.

## High-value follow-up (static and offline)
1. Identify the backing source of the VM byte stream (reader initialization, resource loading, data section pointers).
2. Trace the initial `<Module>::.cctor` call to `FA13B832`: selector argument and initial VM state, then decode the first instructions to find real application call sites.
3. Locate metadata resolution and `WebClient.DownloadString` call sites, establish reachability from decoded bytecode, and recover URL generation and parameters.
4. If necessary, use an already-existing isolated test-VM memory dump as *data*, without relaunching the sample, to seek restored virtual-only method bodies.
5. Document observed vs inferred behavior, indicators, and confidence.

## Safety
Do not run this sample on a host workstation or unisolated environment. This report involved no execution or byte modification.
