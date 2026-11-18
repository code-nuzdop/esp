# SjTNlCHNfW.exe — consolidated static investigation

**Analysis date:** 2026-11-17  
**Method:** Offline inspection of the original EXE, existing IL exports, and an already-collected paused-process Windows minidump. **The executable was not launched or invoked by this analysis.**  
**Status:** Protection and initial VM instruction stream partially recovered. **Underlying application behavior remains unproven.**

## Executive conclusion

The sample is a .NET Framework executable with a substantial VM-based protection/virtualization mechanism. Its metadata and readable strings show a WinForms/Visual Basic-style application and a serial-number activation/deactivation workflow that refers to hardware identifiers, network operations, and hashes. Its CLR module initializer constructs a 256-entry virtual-machine dispatcher, which reads obfuscated instructions from a high-entropy file-backed region. We recovered the complete 256-entry registration map (93 distinct handler functions) and **statically decoded an initial path into a nested VM instruction stream**. This is meaningful progress beyond identifying the VM, but not a full devirtualization of the application.

**The evidence does not establish malware classification** such as RAT, infostealer, downloader, persistence agent, or exfiltrator. Those behaviors require actual invoked API targets/arguments, decoded application code, or trustworthy runtime evidence. The licensing strings are not themselves evidence of malicious behavior.

## Artifact identification and environment

| Item | Result | Basis |
|---|---|---|
| File | `SjTNlCHNfW(1).exe` | User-uploaded original sample |
| Size | 6,783,488 bytes | Original file length |
| SHA-256 | `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40` | Computed from original EXE; identical to earlier sample |
| PE format | PE32 x86-format managed image | PE optional header magic `0x10b` |
| CLR flags | `0x00000001` (`ILONLY`) | CLR header; **neither `32BITREQUIRED` nor `32BITPREFERRED` set** |
| Managed entry point | `0x06000023` | CLR header; declared RVA `0x2050`, in unbacked virtual-only section |
| Metadata | 888 MethodDef rows | Parsed earlier from original metadata |
| Existing process snapshot | `RunnerA-paused.dmp`, ~101.9 MiB | Parsed minidump module list and Memory64List |
| Observed runtime | 64-bit .NET Framework CLR modules | Dump includes `Framework64\\v4.0.30319\\clr.dll` and 64-bit module addresses |

**Important correction to the earlier inspection:** “PE32” describes the file format, not a strict requirement to run as a 32-bit process. The image's CLR flags allow AnyCPU/64-bit execution, and the captured process was using the 64-bit CLR. Thus the VM's architecture-dependent left-shift operation would use its 64-bit path in that captured process.

## Unusual PE layout

| Section | RVA | Virtual size | Raw bytes | Observation |
|---|---:|---:|---:|---|
| `F!_~Pyan` | `0x2000` | `0x3E26CC` | 0 | Entry-point method is here; no original bytes at declared method RVA |
| `0[n6P0.A` | `0x3E6000` | `0x40FEBB` | 0 | Additional virtual-only method RVAs |
| `OVgPD_NR` | `0x7F6000` | 8 | 512 | Short backing section |
| `_kh!cr6M` | `0x7F8000` | `0x676AC8` | 6,777,856 | Near-maximum entropy (~7.997 bits/byte); contains VM data and IL |
| `PF.CT8VA` | `0xE70000` | `0xDAB` | 3,584 | Metadata/resources region |
| `:zqS2t{G` | `0xE72000` | 12 | 512 | Small section |

Earlier method recovery identified **650 file-backed IL methods**, **163 virtual-only methods** and **75 methods with no RVA**. The 75 no-RVA entries include legitimate metadata-only constructs and should not be classified as encrypted methods by default. The missing 163 cannot be recovered by reading their declared RVA in the original file.

### Minidump examination (new)

The captured process listed `C:\\Analysis\\SjTNlCHNfW.exe` at image base `0x00400000` with size `0x00E74000`. Direct parsing of the minidump `Memory64List` reveals:

- **VA `0x00402000`**, length `0x3E3000`: **every byte is zero**, including managed entry point VA `0x00402050`.
- **VA `0x007E6000`**, length `0x411000`: only three nonzero bytes; it does not contain a meaningful recovery of the second virtual-only code region.
- **VA `0x00BF8000`**, length `0x677000`: maps the large file-backed section, matching the original file at tested RVA locations (including `0x7FA6E0`, `0x80054A`, and IL method RVAs).

**Interpretation:** This particular dump was captured too early or in a state that does **not contain reconstructed IL in the empty sections**. It cannot supply the missing entry-point body. It does not prove that those sections would remain empty at every later point in runtime.

## Recovered virtual-machine infrastructure

1. `<Module>::.cctor` (`0x06000001`) executes `newobj 0x060002E3`, loads `null`, pushes decimal selector **8365793** (`0x007FA6E1`), and calls dispatcher `0x060002C1`.
2. VM constructor `6633B699..ctor` (`0x060002E3`) creates the byte reader `A3B21017`, evaluation stack `FB9C7B25`, and dictionary `F49E028B`.
3. A static IL interpreter evaluated only the constructor's 32-bit arithmetic and branches. It recovered **256 distinct keys `0x00..0xFF`** mapped to **93 distinct parameterless delegate handlers**. Full CSV: `vm_opcode_map.csv`.
4. Dispatcher `FA13B832` (`0x060002C1`) calls the reader's `CD90E311` to set a position, pushes a wrapper for its incoming argument(s), then repeatedly reads an encoded byte (`27803C38`, `0x060000D3`), indexes the dictionary and invokes the handler delegate.
5. Reader `5B08298E` (`0x060000DB`) obtains a decoded 32-bit value; reader `3EA86035` (`0x060000D4`) obtains a decoded 16-bit value. Both read through `40AB99A9.14B13C9A` (an RVA-to-address mapper). The byte and integer decoder state depends on cursor and evolving XOR state.
6. `40AB99A9` gets the managed module image base via `Marshal.GetHINSTANCE(typeof(B39F4A82).Module)`; `0x060002EC` has a section-mapping fallback for memory-loaded assemblies. When `Assembly.Location` is nonempty (as in a file-loaded sample), this code returns without building the alternate map, and the resolver can use image base plus RVA.

**Caution:** For the reader, the provided disassemblies are arithmetic-obfuscated IL. Our emulator implements the specific instruction subset used by the observed paths and matches the original file-backed bytes in the dump, but independently collected runtime decoder outputs are not available. Initial trace results below are **static reconstruction**, not observed execution.

## New: the protected initial VM path

Using the original file bytes, initial selector `0x7FA6E1`, 32-bit wraparound, and the method IL, the reader emulation produces the following **instruction-level** path. The virtual machine consumes bytes in descending RVA order.

| Stream | Opcode | Handler | Reconstruction |
|---|---|---|---|
| Outer at `0x7FA6E1` | `0x10` | `B40B1435` (`0x060002D6`) | Read encoded `uint32`, returns `0`; push integer 0 |
| Outer | `0x50` | `8C26AAA4` (`0x060002C0`) | Pop/discard one VM stack item |
| Outer | `0x50` | Same | Pop/discard another stack item (dispatcher had seeded an argument wrapper) |
| Outer | `0x10` | `B40B1435` | Read encoded `uint32` **`0x0080054A`**; push it |
| Outer | `0x53` | `918908BF` (`0x0600029C`) | Nested VM invocation/dispatch using popped encoded selector |

The nested call handler creates a new VM reader, sets its cursor from the integer on the stack, decodes an argument count and other header fields, and invokes a new `6633B699` interpreter using its resulting cursor. Its IL includes the direct call `0x060002C1` from a newly constructed interpreter. This confirms **multiple levels of virtualization**, not merely an inert dictionary.

At nested selector `0x80054A`, reconstructed fields and first instructions are:

| Item | Decoded value | Meaning / limitation |
|---|---:|---|
| 16-bit header field | `0` | Consistent with zero supplied arguments |
| First 32-bit header field | `0` | Possibly return-type identifier; its exact branch role has not been fully validated |
| Second 32-bit header field | `10` | Consumed in the nested-call path; exact significance unresolved |
| Nested opcode | `0x10` | Push encoded integer `0` |
| Nested opcode | `0x50` | Pop/discard integer |
| Nested opcode | `0x40` | Handler `E82B3785` (`0x060002C7`) |

Handler `0x40` calls reader `598A34AE`, consumes four encoded 32-bit values, then calls `A4B0F598.DAA699AD` (`0x06000204`) on a VM support object. The static decoder recovers **two consecutive records** using two different opcode keys (`0x40` and `0xCF`) registered to that same helper:

| Key | Control byte | Operand 1 | Operand 2 | Operand 3 | Operand 4 |
|---|---:|---:|---:|---:|---:|
| `0x40` | `0` | `0x003EA520` | `0x003EA532` | `0x007FEF12` | `0x01000054` |
| `0xCF` | `0` | `0x003EAF6C` | `0x003EAF8A` | `0x007FC0FE` | `0x01000054` |

**New metadata verification:** TypeRef `0x01000054` is explicitly **`System.Exception`** in the original sample's `#~` and `#Strings` metadata. The byte value `0` also matches the conventional catch-clause flag. The apparent start/end pairs in the virtual-only RVA range, followed by a handler selector in the file-backed range and an exception-type token, strongly support **VM catch/exception-region registration** as `E82B3785`'s purpose. This is a structural inference, not a proof that every field means a specific .NET EH table column. It is not evidence of a malicious operation.

After those two records, the decoded nested stream contains `0x10` with operand `0x7C`, then `0x39` with operand **`0x04000195`** (VM field `F10BF79A`, the evaluation stack); `0x39` calls a `FieldInfo` resolver. The next decoded opcode is `0x1A` (`D719AC25`), which pops two VM values and performs value conversion/assignment. The precise object-level effects of that sequence are not fully resolved. Its complete semantics and ensuing control flow are still unresolved; continuing beyond here would require static emulation of this handler and its invoked helper and deeper nesting. Do not misinterpret the next raw encoded bytes as opcodes without applying the intervening operand decoders.

The entry selector `0x7FA6E1` maps to file offset **`0x2CE1`**; the nested selector `0x80054A` maps to file offset **`0x8B4A`**. Both are within the file-backed `_kh!cr6M` section. Their bytes were independently checked against the memory dump.

Detailed trace rows are in `SjTNlCHNfW_verified_vm_trace.csv`; reproduction logic is in `static_reader_emulator.py`, `build_analysis_deliverables.py`, and `inspect_sample_typerefs.py` (requires the original EXE, the saved `Recovery-Step10.zip` and the existing IL disassembly and opcode map). No code in the suspicious executable was executed.

## Selected VM opcode semantics

| Opcode | Handler | Best-supported behavior |
|---|---|---|
| `0x00` | `AF093527` | Float32 arithmetic division through `43233FA0.2BA3942E` |
| `0x01` | `B1190689` | Read encoded integer and resolve/push a VM value |
| `0x02` | `B59103A5` | Float comparison producing custom flags |
| `0x03` | `1C922035` | Architecture-dependent bitwise left shift (int32/int64) |
| `0x04` | `549EC905` | Convert VM unsigned 64-bit value to Float32 wrapper |
| `0x05` | `22B83F93` | Reflection-based `MethodBase`/constructor invocation, argument binding, by-ref handling |
| `0x10` | `B40B1435` | Read encoded uint32 and push signed Int32 VM wrapper |
| `0x40`, `0xCF` | `E82B3785` | Register VM exception/catch-region record (strong structural inference) |
| `0x39` | `7026BDB3` | Decode token and resolve/push `FieldInfo` |
| `0x50` | `8C26AAA4` | Pop/discard VM stack value |
| `0x53` | `918908BF` | Nested VM call with argument/type processing |

**Correction to an earlier analysis stage:** The constructor's register keys place `AF093527` at opcode `0x00`; earlier debugger output had been interpreted one entry out of alignment. The static decoded first opcode `0x10` and subsequent stack operations are compatible with the recovered table.

## Network/licensing and other application evidence

Raw CLR/user strings include:

- `This code requires valid serial number to run. Program will be terminated.`
- `activation.php?code=`, `type=activation&code=`, `&hwid=`, `&hash=`
- `deactivation.php?hash=`, `type=deactivation&hash=`
- A `user-agent` field and an MSIE-compatible user-agent string.

Other metadata includes `WebClient`, `DownloadString`, `ServerDownloadResult`, `ComputeHash`, network interface/physical address-related methods, Windows Forms/Visual Basic scaffolding, and P/Invoke names `shell32.dll` and `kernel32`. These establish **capabilities and references, not runtime reachability or a verified destination**. No specific non-Microsoft activation host, command-and-control URL, exfiltration endpoint, registry persistence key, or malicious file path was confirmed from the inspected static evidence.

`EF8B98AF` (`0x060002B4`) gets a `MemberInfo` from `3300F60E` (`0x06000281`) and validates that it is a `MethodBase`. The module field `0A853884` is initialized by `typeof(6633B699).Module`, and `3300F60E` uses `Module.ResolveMember(int)` against that module. That enables the VM to call methods referenced by the assembly's metadata, including external framework methods. It is not evidence that any particular dangerous method was invoked.

## Defensible indicators

- **File SHA-256:** `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`
- **Distinctive static structure:** unusual zero-raw sections and large high-entropy section, custom VM, 256 opcode keys / 93 targets.
- **Potential network strings:** activation/deactivation URI paths and query parameter names, **not a complete endpoint or IOC suitable for blocking by itself**.
- **Observed image path in captured VM:** `C:\\Analysis\\SjTNlCHNfW.exe` is an analyst's path, **not** a malware installation or persistence path.

## Final assessment and remaining limitations

**High confidence:** highly obfuscated, virtualized .NET/CLR application; VM dispatcher and registration map; root bytecode begins at selector `0x7FA6E1`; a nested call uses selector `0x80054A`; original binary and paused dump have no reconstructed IL in the virtual-only entry-point section; serial-activation-related strings and relevant API metadata are present.

**Moderate confidence:** initial VM instruction-level trace and handler classifications; the integer reader emulation follows recovered IL operations and returns plausible values, but lacks independent dynamic input/output comparisons.

**Unproven:** whether the executable maliciously accesses credentials/files, establishes persistence, downloads/executes code, contacts a particular host, or exfiltrates data. Whether the missing 163 virtual-only method bodies are ever reconstructed later in runtime remains unknown.

**Specific blocker for full application-behavior attribution:** the 0x40 nested handler and several helper layers have not been devirtualized; the original PE has 163 methods without on-disk bodies at their declared RVAs; the existing paused memory capture does not contain restored versions. A later isolated runtime capture *might* supply additional evidence, but no unsafe execution is necessary or recommended on a personal machine. The report therefore stops at the supported boundary rather than inventing the payload's purpose.

## Reproducibility and safety notes

All delivered scripts read on-disk bytes and IL text and perform constrained arithmetic simulation. They do **not** import the EXE as executable code, do **not** load it into the CLR, do **not** spawn it, and do **not** make network requests. Handle the original file, dump and artifacts as untrusted evidence, preferably in a disposable isolated VM or analysis sandbox.
