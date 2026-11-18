# SjTNlCHNfW.exe — Loader + Protector Static Analysis and .NET VM Reverse Engineering

> **Scope:** The evidence describes the executable's managed loader/protection layer and partial VM decoding. It does **not** establish a working aimbot, ESP pipeline, or cheat payload. The 163 MethodDef RVAs in zero-raw executable sections are structurally unbacked in the on-disk image, but their runtime generation is **unverified**.

## Runtime-materialization hypothesis (not demonstrated)

The sections `F!_~Pyan` and `0[n6P0.A` have Code|Execute|Read flags (`0x60000020`) and no file-backed bytes. A write to these pages would require suitable memory protection at the time of writing, **if** protected code is actually materialized there. No `VirtualProtect` event or generated method body has been observed. The zero-filled entry-point RVA `0x2050` does not by itself prove a valid empty `Main` stub. The file-backed `<Module>::.cctor` at RVA `0xA988D8` is an independently verified early initializer. Reflection.Emit and unmanaged allocation references indicate **capability**, not proof of how the 163 declarations are handled.

The custom protector's product/vendor is **unidentified**. The 52-element `D0244F83` array, element 5, reader-cursor control, and the missing method bodies remain unresolved. No verified aimbot/ESP behavior can be asserted.

---

# SjTNlCHNfW.exe — Loader + Protector Static Analysis and .NET VM Reverse Engineering

**Sample SHA-256:** `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`  
**Module MVID:** `25c98968-dcee-4c45-889d-f1773ecb3789`  
**Scope clarification:** This document analyzes the executable’s **loader, licensing-facing artifacts, PE/CLR protection, and custom .NET virtualization**. It is **not** an aimbot/ESP feature analysis, does not recover or verify cheat functionality, and must not be cited as evidence that any game-manipulation feature actually runs. No aimbot, ESP overlay, targeting logic, or in-game behavior was established from the currently decoded instructions.  
**Evidence package validation:** Appendix E source files were verified against the actual archive, including 650 full decoded IL bodies and 650 CFG entries. All original UTF-16 evidence text files have been normalized to UTF-8 in the revised package.  

**Evidence status:** Comprehensive compilation of recoverable evidence, not a claim of total devirtualization.  
**Investigation date:** 17 November 2026 (recompiled from prior static passes).  
**Source sample:** User-provided `SjTNlCHNfW.exe` / `SjTNlCHNfW(1).exe`.  
**Safety and scope:** The reported analysis uses offline PE/CLR metadata parsing, IL decoding, constrained arithmetic/reader simulation, and examination of an earlier paused-process memory dump. The sample was not launched in this analysis. No live network activity is measured.  
**Contents:** Technical findings plus exhaustive 256-key and 93-callback appendices, 124-local-slot appendix, and a separately packaged all-888-method inventory, byte-level IL, static call graph, CFG, decoder scripts and archived historical reports.

> **EVIDENCE WARNING.** "Full details" here means every fact supported by the available analysis artifacts is retained or indexed. It is not technically possible to supply verified semantics for the still-unrecovered protected instructions, absent method bodies, runtime-generated code, or unknown runtime-only values. No invented purpose, host, key, payload, C2 infrastructure, or code path is presented as fact. The appendices and machine-readable evidence package preserve the remaining structural raw data rather than pretending it was semantically decoded.

## 1. Executive determination

**Definitive structural finding:** A .NET Framework managed executable is heavily obfuscated and virtualizes control flow in a custom interpreter, `6633B699`. Its constructor statically registers **256** uint32 opcode keys, using **93** distinct `void()` delegate handlers, and its module initializer dispatches the first protected stream beginning at RVA `0x007FA6E1`. It uses a stateful, descending-RVA byte reader, nested VM calls, metadata-token resolution, typed evaluation-stack values, and wrappers that can redirect the reader cursor while resetting decoder state. Parts of the decoded bytecode initialize **124 typed VM local slots**, build exception-region records, and create a **52-element `uint[]`** used as a potential jump-target table.

**Identified application-facing evidence:** Readable activation/deactivation strings, serial-number gating text, device/hardware-ID and hashing-related names, and references to `WebClient` / `DownloadString`, Windows Forms / Visual Basic assemblies, `shell32.dll`, and `kernel32`. These may reflect license protection, network activation, or other application code; their reachability and precise call arguments are not established.

**What cannot be concluded:** No aimbot/ESP or other cheat feature implementation has been recovered or validated.  The sample is **not proven** to be a stealer, RAT, downloader, infostealer, persistence agent, ransomware, exfiltration tool, or benign licensing-only product. An actual command-and-control endpoint and actual malicious invocation chain were not recovered. This is an **unknown-purpose, high-risk-to-execute protected executable**, not a positively identified malware family.

**Primary unresolved boundary:** Code in the protected initializer uses `76B7C6BB.D0244F83[5]` to feed a reader-cursor assignment. The array's runtime element value is unknown. Failing to emulate this cursor update causes an invalid linear trace. The original file also lacks raw bytes at the declared RVAs of 163 methods, including the CLR entry point. The saved early-process dump does not reconstruct those sections.

## 2. Evidence identity and acquisition

| Property | Value | Evidence/confidence |
|---|---|---|
| Module MVID | `25c98968-dcee-4c45-889d-f1773ecb3789` | Module table Mvid GUID heap index, directly verified against uploaded EXE |
| SHA-256 | `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40` | Locally verified against both uploaded EXE copies |
| File length | **6,783,488 bytes** | File-system measurement |
| Format | PE32 / i386-format, CLR managed | Direct PE/CLR analysis |
| CLR flags | `0x00000001` (`ILONLY`) | Neither `32BITREQUIRED` nor `32BITPREFERRED`; PE32 is **not** evidence the runtime was 32-bit |
| Runtime snapshot | 64-bit .NET Framework CLR (`Framework64\v4.0.30319\clr.dll`) | Earlier `RunnerA-paused.dmp`; not a new runtime execution |
| CLR managed entry-point token | `0x06000023` | RVA `0x2050`, virtual-only unbacked section |
| MethodDef row count | **888** | Metadata enumeration |
| Structural file-backed IL | **650** methods | IL decoding only, not full behavioral proof |
| Virtual-only method RVAs | **163** | Declared RVAs in zero-raw sections |
| No-RVA methods | **75** | Includes legitimate abstract / runtime / interop declarations |
| EXE overlay | **0 bytes** | Last raw section ends at EOF |
| `.NET metadata root` | One `BSJB` root observed | No evidence of a second plain metadata root; encrypted payload still possible |

The supplied EXE copies are byte-identical by hash. The earlier dump is context captured by the user in an isolated test VM; its contents are an observational snapshot of one specific state and **not a later unpacked image**.

## 3. Complete PE section map

| Section name | Virtual RVA | Virtual size | Raw offset | Raw size | Interpretation |
|---|---:|---:|---:|---:|---|
| `F!_~Pyan` | `0x002000` | `0x3E26CC` | `0x0` | `0` | Virtual-only; declared entry-point body belongs here |
| `0[n6P0.A` | `0x3E6000` | `0x40FEBB` | `0x0` | `0` | Second virtual-only range |
| `OVgPD_NR` | `0x7F6000` | `0x8` | `0x400` | `0x200` | Tiny file-backed section |
| `_kh!cr6M` | `0x7F8000` | `0x676AC8` | `0x600` | `0x676C00` | Large, very-high-entropy file-backed IL/VM data section |
| `PF.CT8VA` | `0xE70000` | `0xDAB` | `0x677200` | `0xE00` | CLR metadata/resources-adjacent content |
| `:zqS2t{G` | `0xE72000` | `0xC` | `0x678000` | `0x200` | Small ending section |

Observed entropy for the large section was approximately **7.997 bits/byte**, near the maximum 8. This is consistent with compressed/encrypted/highly transformed material, **not by itself proof of encryption** or malware. The custom section names and no-raw virtual ranges are unusual. Do not read the raw file at `RVA` as if it were an offset; file-backed `_kh!cr6M` RVAs translate to `file_offset = RVA - 0x7F8000 + 0x600` within its valid backing. Example: `0x7FA6E1 → 0x2CE1`; `0x80054A → 0x8B4A`.

**Memory dump limitations:** Earlier memory capture lists the EXE base as `0x00400000`, image size `0x00E74000`. At VA `0x00402000`, a `0x3E3000`-byte region was zero-filled, including VA `0x00402050` (entry point). A `0x411000`-byte region starting VA `0x007E6000` held only three nonzero bytes. File-backed content beginning VA `0x00BF8000` matched the EXE at tested positions. It therefore fails to recover the missing IL at that time, but cannot rule out later restoration.

## 4. Metadata/method inventory and reliability boundaries

Method states: **650 file-backed IL**, **163 virtual-only**, **75 with zero RVA** = **888 total**. For the 650 recoverable methods, structural parsing recorded **2,725 basic blocks**, **3,348 CFG edges**, and **2,561 static invocation references**, of which **1,667** were in-assembly MethodDef references. These are syntactic references; they do not establish that a method executes.

The exact **888-row** `SjTNlCHNfW_recovery_status.csv` gives token, row ID, type/name, RVA, backing, header/decode, instruction count, block count, graph edges, inbound direct-call count, and source note. `SjTNlCHNfW_function_inventory.csv` adds declared IL length, file body position, initial bytes, and prior descriptive triage. `SjTNlCHNfW_pass6_method_provenance.csv` independently records PE backing and method signatures. All are packaged, not abridged.

`SjTNlCHNfW_disassembly.il.txt` includes instruction-by-instruction disassembly of all **650** file-backed methods. `SjTNlCHNfW_control_flow_graphs.json` records all parsed CFG nodes and edges. `SjTNlCHNfW_call_edges.csv` records each syntactic call reference. `SjTNlCHNfW_cleaned_il_view.txt` and candidate classifications provide limited dead-constant suppression for selected methods; these are **analyst reconstructions**, not source-equivalent programs. Metadata method names remain obfuscated. A derived C# view can contain invalid expression types due to control-flow obfuscation; original IL controls such disputes.

**Do not conflate:** `MethodDef` (a method definition), `MemberRef` (a reference to a member, often external), `TypeRef`, `TypeDef`, `TypeSpec`, `FieldDef`, and `MethodSpec` are different metadata table categories. The high-byte token families observed include `0x06` for MethodDef, `0x0A` MemberRef, `0x01` TypeRef, `0x02` TypeDef, `0x1B` TypeSpec, and `0x04` FieldDef. An arbitrary 32-bit value is **not** automatically a valid token simply because a handler expects one.

## 5. VM architecture and dispatch

### 5.1 Root module initialization

Observed file-backed `<Module>::.cctor`, token `0x06000001`, RVA `0x00A988D8`:

```il
IL_0000: newobj 0x060002E3        // 6633B699 .ctor()
IL_0005: ldnull
IL_0006: ldc.i4 8365793          // 0x007FA6E1
IL_000B: call   0x060002C1        // 6633B699.FA13B832(object[], int32)
IL_0010: pop
IL_0011: ret
```

### 5.2 Interpreter, reader, stack, and delegate collection

- Interpreter TypeDef `0x0200006D`, named `6633B699`.
- VM constructor MethodDef `0x060002E3`, IL size **17,437 bytes**.
- Dispatcher `FA13B832`, MethodDef `0x060002C1`, signature equivalent to `object (object[] args, int32 selector)`.
- Reader `A3B21017` (`0x0200002D`), inherits `EAA46804` (`0x02000018`), kept in instance field `0x04000191` / `B32A609B`.
- Evaluation stack `FB9C7B25` stored in instance field `0x04000195` / `F10BF79A`.
- Handler dictionary field `0x04000197` / `F49E028B`, generic signature `Dictionary<uint32, 95969DA2>`.
- Delegate TypeDef row 27 `95969DA2` derives from `System.MulticastDelegate`: `.ctor(object,native int)` MethodDef `0x06000082`; `Invoke():void` MethodDef `0x06000081`.
- Registration indexer MemberRef `0x0A00010C` (`set_Item`); dispatch indexer MemberRef `0x0A000152` (`get_Item`), followed by delegate `Invoke()`.
- Constructor performs 256 callback-registration sites using `ldftn` + delegate constructor + indexed dictionary assignment. Executing only its arithmetic and branch subset statically yielded keys `0x00` through `0xFF`, **all distinct**, with **93 unique handler methods**. Method order is not itself key order; the output mapping is captured in the full 256-row appendix.
- VM dispatcher references byte reader `A3B21017.27803C38` / token `0x060000D3`, sets reader cursor via `CD90E311` / `0x060000D7`, and repeatedly invokes dictionary callbacks.

A source-level sketch, **not** a compilable replacement for all VM behavior:

```csharp
object Dispatch(object[] args, int selector) {
    reader.SetPosition(selector);   // resets rolling state too
    SeedVirtualStack(args);
    while (HasNextVirtualInstruction()) {
        byte key = reader.ReadEncodedByte();
        opcodeHandlers[(uint)key]();
    }
    return CollectVirtualReturnValue();
}
```

The loop termination, exception handling and argument/return mechanics remain partially obfuscated; the sketch identifies the proven components but not every reachable behavior.

### 5.3 General value and helper model

`8F0BF53C` is a VM value abstraction exposing type/conversion and boxing methods; concrete wrappers include `ABA5F297` (signed 32-bit integer), `93BA6F05` (signed 64-bit integer), `43233FA0` (float), reference wrappers such as `8E292119` and `E4113232`, and other support types. The stack's `93329331()` pops, `E61629A6()` pushes, and the local-slot `21A7D23C` assigns a typed slot. Many callbacks are merely adapters: pop values → call helper → wrap → push. High-confidence low-level mechanics can be described without assigning business-level names to all wrappers.

## 6. Encoding, addressing and decoding methods

### 6.1 Physical byte sourcing

File-backed VM bytes are read from a module memory image using the RVA mapper. `40AB99A9` obtains an HINSTANCE/module base using `Marshal.GetHINSTANCE(typeof(B39F4A82).Module)` (mapper initializer `0x060002EC`); mapper resolver `0x060002EB` / `14B13C9A` maps RVAs into readable addresses and has section-map fallback logic. For a normal file-loaded assembly (`Assembly.Location` nonempty), the observed IL path permits module-base + RVA addressing. The mapper includes `BadImageFormatException` paths and fallback records for alternate assembly layouts; the exact behavior of all branches is not fully proven.

### 6.2 Mutable reader fields

- Reader cursor: `A3B21017.D38A0391` / field `0x04000093`.
- Rolling decoder state: `A3B21017.78A03A01` / field `0x04000094`.
- Cursor and state setter `A3B21017.CD90E311(int32)` / method `0x060000D7` assigns **the supplied 32-bit bit pattern to both fields**, on the simplified initial path.
- `0x060000D3` (`27803C38`) reads and decodes one byte (`ldind.u1` via mapper) and updates state.
- `0x060000DB` (`5B08298E`) reads and decodes a 32-bit word (`ldind.u4`) and updates state.
- `0x060000D4` reads a decoded 16-bit value; `0x060000DF` returns a cursor-related field.
- The observed stream's reader cursor moves **toward decreasing RVAs**. The cipher is *stateful*: seek/restart at the same physical byte with a fresh reader can yield a different decoded instruction.

### 6.3 Offline evaluator methodology

The preserved script `static_reader_emulator.py` parses the recovered IL of these reader methods, interprets only a supported instruction subset (`ldloc`, `stloc`, `ldc.i4`, unsigned/signed branch comparisons, `add`, `sub`, `xor`, `and`, `or`, `mul`, `shl`, `shr.un`, `div.un`, `rem.un`, conversion, byte/word memory loads, mapping calls), with **32-bit modulo-2^32 arithmetic**. Shift counts use the correct masked low five bits for 32-bit operations. It reads physical bytes from the original EXE by section mapping, not by loading or executing CLR types. On the observed paths, the selected IL subset is sufficient to reproduce the displayed decoded records.

**Validation evidence:** original EXE hash assertion, readable `TypeRef` / `FieldDef` decoded operands, sequential 0..123 local indices, repeatable instruction templates, and original file bytes matching earlier dump at selected RVAs. These are strong consistency checks, but **not independent runtime test vectors**. Runtime-equivalence for every branch and generic input is unproven. Scripts contain hard-coded file paths for this specific sample and are provided for audit, not reuse as a universal deprotector.

### 6.4 Registration-key arithmetic decoding

`analyze_vm_constructor.py` parses the single constructor `0x060002E3`, models its 32-bit stack/local arithmetic and opaque branches, and records the key passed to each `Dictionary<uint32,delegate>.set_Item` alongside the preceding `ldftn` callback. Unlike naive regex extraction, it evaluates the key arithmetic; the recovered 256-key set was independently sanity checked against the visible registration sites and first observed handlers. The historical earlier WinDbg map had an **off-by-one interpretation**: initial handlers are `0x00=AF093527`, `0x01=B1190689`, `0x02=B59103A5`, `0x03=1C922035`.

### 6.5 Dynamic reader redirection is part of the protected control flow

Opcode `0x39` (`7026BDB3` / `0x0600027B`) constructs an `E4113232` reference wrapper against a reflected `FieldInfo`. When that wrapper refers to field `0x04000191` (the current VM reader), its `5F11D60F(object)` setter (MethodDef `0x060000B0`) obtains the **existing reader object** using `FieldInfo.GetValue(instance)`, casts to `EAA46804`, and calls its virtual `CD90E311(int32)`. It **does not replace the reader field** via `FieldInfo.SetValue`. That path resets the reader's **cursor and cipher state**. Distinct wrapper `8E292119`, created by opcode `0x12`, does use `FieldInfo.SetValue` for ordinary field assignment. This distinction corrects two earlier interpretations (reader replacement and a reliable post-assignment linear read).

The actual cursor argument in the second nested stream comes from a protected `uint[]` lookup. Until its concrete runtime value is known, the next instruction address is **unknown**, even though the next *physical byte* in the old stream is known.

## 7. Decoder states, nested streams and recovered instruction paths

### 7.1 Outer interpreter at RVA `0x007FA6E1`

| Sequence | Opcode | Handler | Decoded effect / operand |
|---:|---|---|---|
| 1 | `0x10` | `B40B1435` | Encoded integer `0` → push |
| 2 | `0x50` | `8C26AAA4` | Stack pop/discard |
| 3 | `0x50` | `8C26AAA4` | Second stack pop/discard, against VM-seeded stack |
| 4 | `0x10` | `B40B1435` | Encoded integer `0x0080054A` → push |
| 5 | `0x53` | `918908BF` | Nested invocation with selector `0x0080054A` |

### 7.2 First nested stream at RVA `0x0080054A`

Decoded header: `ushort 0`, `uint32 0`, `uint32 10`; precise roles of the two 32-bit header fields remain partially unresolved. Early instructions include `0x10` push-zero, `0x50` discard, and `0x40` / `0xCF` aliases calling `E82B3785` to consume two structurally similar four-operand records:

| Key | Clause/control | First RVA | Second RVA | Handler RVA | Type token |
|---|---:|---|---|---|---|
| `0x40` | `0` | `0x003EA520` | `0x003EA532` | `0x007FEF12` | `0x01000054` |
| `0xCF` | `0` | `0x003EA532` | `0x003EA543` | `0x007FEF12` | `0x01000054` |

Metadata TypeRef `0x01000054` is **`System.Exception`**. The zero control flag and code ranges support an exception-region/catch registration interpretation, but their exact column-level meaning requires the helper `A4B0F598.DAA699AD` (`0x06000204`) and runtime semantics. The nested stream subsequently references stack field `0x04000195` and assignment operation `0x1A`, then enters a repeated typed-local sequence.

### 7.3 Critical stateful decoder correction

The first continuation had constructed a **new reader** at RVA `0x80050B`; this erroneously yielded opcode `0x74` and operand `0xCC470010`. The correct continuation after 23 earlier reads retains `D38A0391=0x0080050B` and rolling decoder state `78A03A01=0x04802B4D` and decodes opcode `0x01`, operand `0`. Therefore the old `0x74` path **must not** be treated as actual code.

### 7.4 Typed local-slot initialization

There are **124 consecutive four-instruction groups**, numbered `0..123`, consuming **496 instructions**. The repeated template is:

1. Opcode `0x01` or `0xC3` (handler `B1190689`) with encoded integer `0`.
2. Opcode `0x10` (`B40B1435`) with encoded integer `0`.
3. Opcode `0x10` (`B40B1435`) with encoded `.NET` type token.
4. One of `0xA8`, `0xC4`, `0xE3`, `0x54`, `0x70`, or `0x77` (all map to `76862C12`) with a 16-bit sequential local index.

`76862C12` resolves type and slot information, performs conversion/default-value handling, and stores via `FB9C7B25.21A7D23C`. The first VM value is resolved through an additional helper, so these records should be called **typed local initialization**, not blindly claimed to be primitive zeros. `54` slots use `System.UInt32`, `13` use `System.Int32`, `5` use `System.Int64`, `4` use `System.IntPtr`, `4` use `System.Boolean`; **22 TypeSpec** and **7 TypeDef** entries were not fully resolved into meaningful names, while the rest are resolved TypeRefs. The full 124-slot table is appended below.

After these groups: opcode `0x50` at RVA `0x007FFC53`, then opcode `0x10` with selector `0x007FE224`, then `0x53` nested invocation.

### 7.5 Second nested stream at RVA `0x007FE224`

Header: `ushort 0`, `TypeRef 0x01000058` = `System.UInt32`, and `TypeRef 0x01000066` = `System.Enum`. In sequence, the verified static reader emits stack setup (`0x10`, `0x50`, `0x50`), value resolver `0xC3`, field-reference `0x12` with `FieldDef 0x04000182` (`76B7C6BB.D0244F83`), type conversion `0x0D`, push integer `5`, array element access opcode `0x95` with type `System.UInt32`, conversion `0x24`, push integer `0`, cursor-reference wrapper opcode `0x39` for `FieldDef 0x04000191` (`6633B699.B32A609B`), and typed assignment `0x1A`.

The stream therefore uses or attempts to use **array element 5** to set its reader cursor. The last decoded instruction leaves reader at old RVA `0x007FE1EE` (emulator state `D38A0391=0x007FE1EE`, `78A03A01=0x007FE252` **before any successful semantic cursor reset**). If the reader were unchanged, the next byte would decode to `0x9C`, operand `0xF735885A`. That operand fails the method-token shape check and is **not evidence of an actual invocation**. The old physical byte cannot safely be decoded as the next executed byte.

### 7.6 Protected jump-array initializer at RVA `0x007FC7AF`

The static field `76B7C6BB.D0244F83` has signature `System.UInt32[]`, `FieldDef 0x04000182`. Type initializer `76B7C6BB..cctor`, MethodDef `0x06000239`, delegates to VM selector `0x007FC7AF`. Its first **20 read records** statically decode to push zero; discard twice; push integer **52**; `0x1B` with `System.UInt32` to call `Array.CreateInstance`; resolve VM value; create static-field reference with `0x12`; typed assignment `0x1A`; resolve another value, push zero, construct reader cursor wrapper `0x39` against `0x04000191`, and typed assignment `0x1A`.

The static reader cursor after the excerpt is `0x007FC783`. Because the last operation may jump, this physical location is not automatically the next instruction. Nothing verified yet gives the element `D0244F83[5]` a numerical value: array allocation and assigning the array field are not element population. The earlier dump did not supply a verified fully initialized copy.

### 7.7 Exact trace preservation

Evidence files `SjTNlCHNfW_verified_vm_trace.csv`, `SjTNlCHNfW_recovered_nested_local_init.csv`, `SjTNlCHNfW_second_nested_trace.csv`, and `SjTNlCHNfW_new_reader_jump_evidence.csv` preserve the instruction/operand-level records including RVAs, read kinds, and encoded values. They are **decoded read sequences**, not an independently observed dynamic trace. Section 15 below prints the final 43 records verbatim from the verified reader-jump CSV.

## 8. Opcode behavior: resolved and unresolved

The **full 256-key mapping** is appended in Section 13. An opcode and a method name are not a semantic explanation. The following are behaviors substantiated by IL or the cited helper output; any remaining aliases share the listed handler but may have distinct encoded byte values.

| Opcode(s) | Handler / MethodDef | Mechanism | Evidence grade |
|---|---|---|---|
| `0x00` | `AF093527` / `0x0600029F` | Pop two values → helper `43233FA0.2BA3942E` → push Float32 division result | Decompilation-derived helper classification; path not independently runtime tested |
| `0x01`, `0xC3` | `B1190689` / `0x0600029D` | Read encoded int32, resolve VM value, push | IL-supported |
| `0x02` | `B59103A5` / `0x060002D2` | Pop two, float conversion/comparison helper `43233FA0.A229B4BC`, push custom result flags (`1` equal, `0` greater/equal excluding equality, `4` less/unordered) | Arithmetic-obfuscated helper reconstructed; precise special-value behavior conditional on underlying `float` comparison |
| `0x03` | `1C922035` / `0x0600028E` | Native-width left shift; 32-bit helper `ABA5F297.8608E7A7` / `0x06000361`, shift `& 31`; 64-bit helper `93BA6F05.9B91431C` / `0x060001BB`, shift `& 63` | Direct decompilation and constant simplification |
| `0x04` | `549EC905` / `0x0600028A` | Pop, helper `43233FA0.E43B02BB` / `0x060000FA`: unsigned 64-bit to single-precision float wrapper | Decompiled helper |
| `0x05` | `22B83F93` / `0x060002B0` | Resolve `MethodBase`; prepare arguments; by-ref updates; constructor/method invocation; optional `DynamicMethod` emission path; push non-void return | Direct C#/IL evidence for capability, runtime reachability unknown |
| `0x0D` | `DF3D6327` | Type conversion | Trace and helper evidence; conversion details depend on concrete value wrapper |
| `0x10` | `B40B1435` / `0x060002D6` | Read encoded uint32/int and push signed 32-bit VM value | IL/reader trace |
| `0x12` | `35A1509D` | Resolve FieldDef and construct ordinary field-reference wrapper (`8E292119`) | IL/source evidence |
| `0x1A` | `D719AC25` / `0x06000296` | Typed VM assignment (destination pop, source pop, type conversion, virtual setter) | Direct IL/virtual-method chain |
| `0x1B` | `79AF42A2` / `0x060002B5` | `Array.CreateInstance` for decoded element type and length | Direct MemberRef and trace |
| `0x24` | `C9BF0D8B` | Value conversion with specified type token | Trace/helper evidence |
| `0x39` | `7026BDB3` / `0x0600027B` | Create special field-reference wrapper (`E4113232`); on reader field, setter resets cursor and state | Cross-checked virtual setter chain |
| `0x40`, `0xCF` | `E82B3785` / `0x060002C7` | Four-operand VM exception-region registration helper | Strong structural inference (`System.Exception` type token) |
| `0x50` | `8C26AAA4` / `0x060002C0` | Pop/discard stack item | IL/trace |
| `0x53` | `918908BF` / `0x0600029C` | Nested VM dispatch/arg-header handling | IL/trace |
| `0x95` | `C5931FB9` | `Array.GetValue` / array element access | Trace and helper reference |
| `0xA8`, `0xC4`, `0xE3`, `0x54`, `0x70`, `0x77` | `76862C12` | Typed VM local-slot definition/assignment, 16-bit index | Repeated validated trace |

**Remaining 93-callback semantics:** The appendix prints each handler's MethodDef token, alias count, direct call category, instruction count, and direct targets. `SjTNlCHNfW_93_callback_semantic_inventory.csv` gives the original full targets, IL operations and literals. **Do not** upgrade heuristic categories like "internal helper calls" or "reflection/emission" to proof of a real malicious capability.

## 9. Method/member resolution and reflection bridge

**Method resolver chain:** `EF8B98AF(int)` (`0x060002B4`) calls `3300F60E(int)` (`0x06000281`) and checks that returned `MemberInfo` is `MethodBase`, otherwise throws `InvalidOperationException`. `3300F60E` uses the cached module field `0A853884` (`System.Reflection.Module`) and `Module.ResolveMember(int32)`, with a static `Dictionary<uint32, object>` cache guarded by locking. The module field is initialized from `typeof(6633B699).Module`, i.e. the CLR module containing the VM class. Metadata can reference framework methods in **external assemblies** through MemberRef; self-module resolution doesn't imply that all targets are internal code.

The invocation handler `22B83F93` includes `MethodBase.CallingConvention`, `GetParameters`, `Type.GetMethod`, `MethodInfo.ReturnType`, `MethodBase.IsStatic`, `IsVirtual`, `IsFinal`, `IsConstructor`, and `ConstructorInfo.Invoke`. It builds argument arrays, supports value conversion, instance receivers, `out` / `ref` bookkeeping using a dictionary of VM references, invokes methods or constructors, copies back by-reference results, and pushes a VM-wrapped return value for non-void methods. Some paths create and cache `DynamicMethod` objects using `System.Reflection.Emit.ILGenerator` and `OpCodes.Call/Ret`. This is a general-purpose VM execution bridge **capable of invoking arbitrary resolvable .NET members, subject to runtime policy, parameters, and actual bytecode**; no specific external member invocation is verified from these available paths.

The 93-handler inventory notes **22 callbacks with external MemberRef calls**, **71 without direct external calls**; **6 with direct reflection/Reflection.Emit**, **6 with type inspection**, **13 containing throw**, and **2 writing fields** (historical static counts, not independently re-audited here). The pop helper is directly referenced by 78 callbacks; push helper by 80. Selected callbacks include `0x06000287` (cache / dynamic method), `0x060002CE` (invocation binder), `0x060002BD` (value-type initialization), `0x060002AF` (nullable/uninitialized object logic), `0x060002D5` (`Marshal.AllocHGlobal`), and `0x06000283` (type validation). Full evidence and call edges are included separately.

## 10. Application-facing strings, APIs and plausible meaning

**Directly observed string fragments:**

```text
This code requires valid serial number to run. Program will be terminated.
activation.php?code=
type=activation&code=
&hwid=
&hash=
deactivation.php?hash=
type=deactivation&hash=
user-agent
```

The earlier string scan also found an MSIE-compatible browser user-agent string, `ServerDownloadResult`, `ComputeHash`, and network interface / physical-address-related names. Static managed references include `WebClient`, `DownloadString`, Windows Forms / Visual Basic support; P/Invoke module names include `shell32.dll` and `kernel32`. These **support a license/activation workflow hypothesis** (serial + HWID + hash + HTTP request); they do **not** prove the program contacts a given domain, uses the endpoint in a reachable path, sends secrets, or is legitimate. No full non-Microsoft destination host/URL with validated code path was established. No supplied report independently identifies actual outbound traffic, registry Run keys, scheduled tasks, service installation, injection, credential database access, cookie/browser secret access, or malicious file creation.

**Treat as leads, not IOCs:** bare `activation.php` / `deactivation.php` path fragments and query keys may occur in benign activation logic. A bare library API reference can also belong to VM support or dead/unused code. False positives can be avoided by distinguishing static capability from invoked application behavior.

## 11. Unresolved methods, missing entry point and confidence assessment

The CLR EntryPoint MethodDef `0x06000023` claims RVA `0x2050`, but file data for its containing section are absent. **No honest full source or exact behavior** can be reconstructed from that RVA. The other 162 virtual-only methods share this problem. A virtual-only method can possibly be populated or redirected at runtime, but the available early dump did **not** reveal that event. No-RVA declarations may be fully legitimate CLR metadata definitions; treating all 75 as encrypted code would be erroneous.

The protected `76B7C6BB.D0244F83` array is declared length 52. The **runtime value** at index 5, and even whether the relevant code path successfully performs that read, remain unknown. A reliable continuation would require a complete symbolic VM: reference identity, stack aliasing, per-method frames, static field storage, array contents, branch feasibility, exception tables, nested reader state, virtual calls and runtime CLR member resolution. The protected initializer itself performs another cursor reset before observed element population.

**Confidence matrix:**

| Statement | Confidence | Limit |
|---|---|---|
| Original EXE identity, PE headers, section backing, MethodDef counts | High | Directly checked against file / inventories |
| `256` opcode keys mapped to `93` handler names | High for statically evaluated constructor | Constructor evaluator supports observed IL paths, not all unforeseen CLR behaviors |
| Module initializer starts VM with `0x7FA6E1` | High | Static IL, not independent execution trace |
| Initial decoded reader streams, 124 local slots and 52-element array allocation | Moderate-high | Repeatable offline byte+IL simulation; no runtime decoder output comparison |
| Exception registration meaning of four-operand records | Moderate | Structural inference, not EH table runtime proof |
| Typed assignment and reader-cursor reset mechanism | High for helper calls, moderate for the particular runtime path | Stack types and successful assignment still need complete simulation |
| Activation/deactivation code is reachable and contacts a server | Unproven | Strings/API metadata only |
| Credential theft, persistence, exfiltration, C2, malware family | Unproven | No payload-level invocation chain or network trace |
| Innocuous / safe to execute | Unproven | Obfuscation and static silence do not establish safety |

**Historical corrections to retain:** (i) PE32 does not mean 32-bit-required; captured CLR was 64-bit. (ii) First three initial opcode assignments had been offset; static map starts `0x00=AF093527`. (iii) The reset-at-`0x80050B` opcode `0x74` was a decoder artifact; with preserved state it is `0x01`. (iv) The second-stream `0x9C` is a **conditional stale-reader** continuation, not a proven executed opcode. (v) The reader was not proved "replaced"; the wrapper's actual implementation calls a cursor/state setter on the current reader. (vi) Preexisting heuristic callback labels and C# decompilation inaccuracies must remain qualified.

## 12. Repeatable methodology, audit instructions and evidence handling

**Workflow performed:** preserve original EXE SHA-256 → parse DOS/PE/CLR headers → map sections and raw backing → parse CLR metadata table rows/signatures → structurally decode file-backed IL and call/branch graph → extract VM registration constructor → evaluate uint32 opaque-key arithmetic offline → resolve method/helper tokens → emulate reader IL opcodes against original bytes → validate known TypeRef/FieldDef values and sequential local registrations → trace nested selectors → stop before unresolved reader-cursor mutations → compare early memory dump's mapped regions → preserve CSV/JSON/IL/scripts and historical findings.

**Minimal offline reproduction commands (in an isolated Python analysis environment with the original EXE and supporting recovered IL ZIP):**

```bash
python analyze_vm_constructor.py
python recover_vm_nested_locals.py
python verify_reader_jump.py
```

Scripts are sample-specific and may overwrite derived CSVs, so use copies when auditing. They do not launch the EXE or connect to network services. The source files are included with a dependency manifest, so a reviewer can examine every assumption. The source IL used by the reader emulator comes from the original EXE or the saved Recovery-Step10 archive, which is included. For independent verification, regenerate the CSV tables and compare file hashes.

**Evidence/security guidance:** Keep the EXE and the earlier process dump isolated. Do not double-click the executable, import it into a CLR session for "analysis", disable endpoint protection to share it, or upload the 102 MB dump to arbitrary public services (it can contain sensitive process memory). The final ZIP intentionally **does not contain the executable or dump**; these already exist separately in your evidence set. The ZIP includes read-only reconstructions, not a runnable variant of the sample.

### Deliverable structure

- `MASTER_comprehensive_report.md` — this full technical narrative and **all 256 mappings + 93 callback summary + 124 local slots + 43 final decoded records**.
- `MASTER_comprehensive_report.pdf` — searchable reading edition of the same report.
- `evidence/` — complete metadata and method inventories (888 rows), mapping sites (256 rows), CFG/call graphs and 650-body IL, callback dependencies, traces, and earlier static reports.
- `scripts/` — offline parsers and constrained reader/constructor emulators used in previous passes.
- `historical/` — prior pass reports and their corrected caveats; preserve provenance, but **newer corrections take precedence** where old reports disagree.
- `MANIFEST_SHA256.txt` — cryptographic inventory of bundled artifacts.

## 13. Appendix A — Every reconstructed opcode-to-handler registration (256/256)

**Columns:** decoded byte/key, decimal key, obfuscated instance-handler name, registration IL offset. This is a **complete dictionary mapping**, not a complete semantic devirtualization. Identical handler names occur under multiple distinct opcode bytes. Each registration maps into TypeDef `6633B699` and the delegate type `95969DA2`.

| Opcode | Decimal | Registered handler | Constructor site |
|---|---:|---|---|
| `0x00` | 0 | `AF093527()` | `IL_00FD` |
| `0x01` | 1 | `B1190689()` | `IL_014D` |
| `0x02` | 2 | `B59103A5()` | `IL_018F` |
| `0x03` | 3 | `'1C922035'()` | `IL_01C8` |
| `0x04` | 4 | `'549EC905'()` | `IL_0219` |
| `0x05` | 5 | `'22B83F93'()` | `IL_025F` |
| `0x06` | 6 | `D3052B17()` | `IL_0293` |
| `0x07` | 7 | `CD3F76B2()` | `IL_02CD` |
| `0x08` | 8 | `'21026DA1'()` | `IL_0309` |
| `0x09` | 9 | `A12F070C()` | `IL_035D` |
| `0x0A` | 10 | `'7106D89C'()` | `IL_03AC` |
| `0x0B` | 11 | `A70C929E()` | `IL_03E5` |
| `0x0C` | 12 | `A1A14C36()` | `IL_041B` |
| `0x0D` | 13 | `DF3D6327()` | `IL_0465` |
| `0x0E` | 14 | `C7154D83()` | `IL_04A3` |
| `0x0F` | 15 | `'14B8FDA4'()` | `IL_04E7` |
| `0x10` | 16 | `B40B1435()` | `IL_052E` |
| `0x11` | 17 | `'9D21EEA9'()` | `IL_055C` |
| `0x12` | 18 | `'35A1509D'()` | `IL_05A0` |
| `0x13` | 19 | `'1101EC8C'()` | `IL_05E4` |
| `0x14` | 20 | `BA870B21()` | `IL_0642` |
| `0x15` | 21 | `AFA5D200()` | `IL_068E` |
| `0x16` | 22 | `'8B1A351C'()` | `IL_06E4` |
| `0x17` | 23 | `'3BAD442A'()` | `IL_0722` |
| `0x18` | 24 | `AF908ABB()` | `IL_0763` |
| `0x19` | 25 | `'3EB2FA2F'()` | `IL_0797` |
| `0x1A` | 26 | `D719AC25()` | `IL_07C5` |
| `0x1B` | 27 | `'79AF42A2'()` | `IL_0803` |
| `0x1C` | 28 | `'21803F9F'()` | `IL_0843` |
| `0x1D` | 29 | `'05B08081'()` | `IL_08A5` |
| `0x1E` | 30 | `'800AB499'()` | `IL_08EB` |
| `0x1F` | 31 | `BD3588B7()` | `IL_0911` |
| `0x20` | 32 | `B839B220()` | `IL_0945` |
| `0x21` | 33 | `'5931DC83'()` | `IL_0986` |
| `0x22` | 34 | `'8C379AB2'()` | `IL_09C4` |
| `0x23` | 35 | `'5D26C703'()` | `IL_0A12` |
| `0x24` | 36 | `C9BF0D8B()` | `IL_0A50` |
| `0x25` | 37 | `'4435311D'()` | `IL_0A76` |
| `0x26` | 38 | `FC0F1D31()` | `IL_0ABA` |
| `0x27` | 39 | `AE2F9A26()` | `IL_0AEC` |
| `0x28` | 40 | `B0964A39()` | `IL_0B28` |
| `0x29` | 41 | `'89A2E63B'()` | `IL_0B7E` |
| `0x2A` | 42 | `'64A9A13F'()` | `IL_0BC8` |
| `0x2B` | 43 | `FBA6060E()` | `IL_0C16` |
| `0x2C` | 44 | `'6CB9379B'()` | `IL_0C50` |
| `0x2D` | 45 | `'6D996612'()` | `IL_0C7E` |
| `0x2E` | 46 | `C983FEBF()` | `IL_0CB4` |
| `0x2F` | 47 | `DBA84833()` | `IL_0CF2` |
| `0x30` | 48 | `'5EA8F02F'()` | `IL_0D49` |
| `0x31` | 49 | `'3C806315'()` | `IL_0DA0` |
| `0x32` | 50 | `B1A9FC34()` | `IL_0DE8` |
| `0x33` | 51 | `'74B39F1C'()` | `IL_0E16` |
| `0x34` | 52 | `A302862D()` | `IL_0E58` |
| `0x35` | 53 | `'9DB004B4'()` | `IL_0E8E` |
| `0x36` | 54 | `CEB29D2C()` | `IL_0ED8` |
| `0x37` | 55 | `'7326F70C'()` | `IL_0F21` |
| `0x38` | 56 | `'4935572B'()` | `IL_0F57` |
| `0x39` | 57 | `'7026BDB3'()` | `IL_0F8D` |
| `0x3A` | 58 | `AE967FAB()` | `IL_0FC3` |
| `0x3B` | 59 | `BC0FF3AE()` | `IL_1005` |
| `0x3C` | 60 | `D9B2E438()` | `IL_1043` |
| `0x3D` | 61 | `'478FD68B'()` | `IL_1079` |
| `0x3E` | 62 | `C5931FB9()` | `IL_10BD` |
| `0x3F` | 63 | `'879D4733'()` | `IL_10FB` |
| `0x40` | 64 | `E82B3785()` | `IL_114B` |
| `0x41` | 65 | `EB2248B9()` | `IL_1191` |
| `0x42` | 66 | `CD3F76B2()` | `IL_11D7` |
| `0x43` | 67 | `'513EF216'()` | `IL_1211` |
| `0x44` | 68 | `'792359AC'()` | `IL_124F` |
| `0x45` | 69 | `'019272A0'()` | `IL_129E` |
| `0x46` | 70 | `'7603EE86'()` | `IL_12CC` |
| `0x47` | 71 | `'1A100412'()` | `IL_12F2` |
| `0x48` | 72 | `'91AF9321'()` | `IL_1348` |
| `0x49` | 73 | `'71BAFF88'()` | `IL_1394` |
| `0x4A` | 74 | `CD970A3D()` | `IL_13CE` |
| `0x4B` | 75 | `'1C856C10'()` | `IL_1414` |
| `0x4C` | 76 | `'1B9A0FA8'()` | `IL_1473` |
| `0x4D` | 77 | `'9C1EF127'()` | `IL_14B9` |
| `0x4E` | 78 | `B51FB5B5()` | `IL_14EB` |
| `0x4F` | 79 | `'6BBB0B8D'()` | `IL_1521` |
| `0x50` | 80 | `'8C26AAA4'()` | `IL_1568` |
| `0x51` | 81 | `'86043CA7'()` | `IL_15A6` |
| `0x52` | 82 | `A70C929E()` | `IL_15E2` |
| `0x53` | 83 | `'918908BF'()` | `IL_163A` |
| `0x54` | 84 | `'76862C12'()` | `IL_1698` |
| `0x55` | 85 | `'99BED52B'()` | `IL_16E0` |
| `0x56` | 86 | `'1D3F64BC'()` | `IL_171A` |
| `0x57` | 87 | `D1934D8B()` | `IL_174C` |
| `0x58` | 88 | `'50080737'()` | `IL_1782` |
| `0x59` | 89 | `'34B71D07'()` | `IL_17C6` |
| `0x5A` | 90 | `'3526928B'()` | `IL_1804` |
| `0x5B` | 91 | `'6D36168F'()` | `IL_1822` |
| `0x5C` | 92 | `'4F2680A8'()` | `IL_1868` |
| `0x5D` | 93 | `'85040E1F'()` | `IL_18A4` |
| `0x5E` | 94 | `'7A15E31B'()` | `IL_1901` |
| `0x5F` | 95 | `'85040E1F'()` | `IL_193B` |
| `0x60` | 96 | `'1D3F64BC'()` | `IL_1981` |
| `0x61` | 97 | `B59103A5()` | `IL_19BF` |
| `0x62` | 98 | `'9D21EEA9'()` | `IL_1A10` |
| `0x63` | 99 | `'9DB004B4'()` | `IL_1A57` |
| `0x64` | 100 | `'513EF216'()` | `IL_1A8D` |
| `0x65` | 101 | `B59103A5()` | `IL_1AED` |
| `0x66` | 102 | `'9D21EEA9'()` | `IL_1B1B` |
| `0x67` | 103 | `DBA84833()` | `IL_1B49` |
| `0x68` | 104 | `'9D21EEA9'()` | `IL_1B7A` |
| `0x69` | 105 | `'21803F9F'()` | `IL_1BC3` |
| `0x6A` | 106 | `'8B1A351C'()` | `IL_1BF9` |
| `0x6B` | 107 | `'9D21EEA9'()` | `IL_1C4F` |
| `0x6C` | 108 | `BD3588B7()` | `IL_1C99` |
| `0x6D` | 109 | `B59103A5()` | `IL_1CE3` |
| `0x6E` | 110 | `B59103A5()` | `IL_1D2F` |
| `0x6F` | 111 | `AF908ABB()` | `IL_1D6B` |
| `0x70` | 112 | `'76862C12'()` | `IL_1D91` |
| `0x71` | 113 | `'85040E1F'()` | `IL_1DCA` |
| `0x72` | 114 | `A1A14C36()` | `IL_1E09` |
| `0x73` | 115 | `FC0F1D31()` | `IL_1E45` |
| `0x74` | 116 | `'8C379AB2'()` | `IL_1E83` |
| `0x75` | 117 | `FBA6060E()` | `IL_1ED5` |
| `0x76` | 118 | `'34B71D07'()` | `IL_1F1F` |
| `0x77` | 119 | `'76862C12'()` | `IL_1F57` |
| `0x78` | 120 | `'513EF216'()` | `IL_1F93` |
| `0x79` | 121 | `'85040E1F'()` | `IL_1FCC` |
| `0x7A` | 122 | `'05B08081'()` | `IL_2025` |
| `0x7B` | 123 | `BC0FF3AE()` | `IL_2074` |
| `0x7C` | 124 | `'8C379AB2'()` | `IL_20BD` |
| `0x7D` | 125 | `'1A100412'()` | `IL_20F9` |
| `0x7E` | 126 | `'74B39F1C'()` | `IL_212F` |
| `0x7F` | 127 | `AF908ABB()` | `IL_2168` |
| `0x80` | 128 | `A302862D()` | `IL_219E` |
| `0x81` | 129 | `'5931DC83'()` | `IL_2200` |
| `0x82` | 130 | `'5931DC83'()` | `IL_224F` |
| `0x83` | 131 | `'3C806315'()` | `IL_2299` |
| `0x84` | 132 | `BC0FF3AE()` | `IL_22D3` |
| `0x85` | 133 | `'6CB9379B'()` | `IL_230B` |
| `0x86` | 134 | `'9D21EEA9'()` | `IL_2352` |
| `0x87` | 135 | `BD3588B7()` | `IL_2394` |
| `0x88` | 136 | `A1A14C36()` | `IL_23C8` |
| `0x89` | 137 | `A1A14C36()` | `IL_2409` |
| `0x8A` | 138 | `B839B220()` | `IL_2453` |
| `0x8B` | 139 | `AF093527()` | `IL_2489` |
| `0x8C` | 140 | `AF093527()` | `IL_24D3` |
| `0x8D` | 141 | `'8C379AB2'()` | `IL_250D` |
| `0x8E` | 142 | `'21026DA1'()` | `IL_2567` |
| `0x8F` | 143 | `'89A2E63B'()` | `IL_25A5` |
| `0x90` | 144 | `'800AB499'()` | `IL_25FC` |
| `0x91` | 145 | `'3EB2FA2F'()` | `IL_262E` |
| `0x92` | 146 | `EB2248B9()` | `IL_266C` |
| `0x93` | 147 | `'34B71D07'()` | `IL_26AA` |
| `0x94` | 148 | `'9D21EEA9'()` | `IL_26FF` |
| `0x95` | 149 | `C5931FB9()` | `IL_274B` |
| `0x96` | 150 | `DBA84833()` | `IL_279D` |
| `0x97` | 151 | `FC0F1D31()` | `IL_27E6` |
| `0x98` | 152 | `'21803F9F'()` | `IL_2845` |
| `0x99` | 153 | `'21803F9F'()` | `IL_2883` |
| `0x9A` | 154 | `BD3588B7()` | `IL_28C9` |
| `0x9B` | 155 | `'6BBB0B8D'()` | `IL_2923` |
| `0x9C` | 156 | `'74B39F1C'()` | `IL_297B` |
| `0x9D` | 157 | `B839B220()` | `IL_29B4` |
| `0x9E` | 158 | `BD3588B7()` | `IL_29EA` |
| `0x9F` | 159 | `'8C379AB2'()` | `IL_2A2B` |
| `0xA0` | 160 | `'6D36168F'()` | `IL_2A65` |
| `0xA1` | 161 | `A1A14C36()` | `IL_2AAB` |
| `0xA2` | 162 | `'9D21EEA9'()` | `IL_2AEC` |
| `0xA3` | 163 | `'3BAD442A'()` | `IL_2B4C` |
| `0xA4` | 164 | `A1A14C36()` | `IL_2B95` |
| `0xA5` | 165 | `BC0FF3AE()` | `IL_2BE1` |
| `0xA6` | 166 | `AE967FAB()` | `IL_2C33` |
| `0xA7` | 167 | `'5931DC83'()` | `IL_2C61` |
| `0xA8` | 168 | `'76862C12'()` | `IL_2CBF` |
| `0xA9` | 169 | `DBA84833()` | `IL_2D03` |
| `0xAA` | 170 | `FC0F1D31()` | `IL_2D48` |
| `0xAB` | 171 | `A1A14C36()` | `IL_2D8C` |
| `0xAC` | 172 | `'34B71D07'()` | `IL_2DCE` |
| `0xAD` | 173 | `'1C922035'()` | `IL_2E33` |
| `0xAE` | 174 | `'879D4733'()` | `IL_2E88` |
| `0xAF` | 175 | `'4935572B'()` | `IL_2EBE` |
| `0xB0` | 176 | `'22B83F93'()` | `IL_2EFF` |
| `0xB1` | 177 | `B839B220()` | `IL_2F2D` |
| `0xB2` | 178 | `'34B71D07'()` | `IL_2F63` |
| `0xB3` | 179 | `B839B220()` | `IL_2FA5` |
| `0xB4` | 180 | `'5931DC83'()` | `IL_2FF6` |
| `0xB5` | 181 | `A1A14C36()` | `IL_3024` |
| `0xB6` | 182 | `'86043CA7'()` | `IL_307E` |
| `0xB7` | 183 | `'6CB9379B'()` | `IL_30CA` |
| `0xB8` | 184 | `FC0F1D31()` | `IL_3100` |
| `0xB9` | 185 | `'21803F9F'()` | `IL_313E` |
| `0xBA` | 186 | `'34B71D07'()` | `IL_3187` |
| `0xBB` | 187 | `'74B39F1C'()` | `IL_31E0` |
| `0xBC` | 188 | `'99BED52B'()` | `IL_322A` |
| `0xBD` | 189 | `'74B39F1C'()` | `IL_325B` |
| `0xBE` | 190 | `'50080737'()` | `IL_32B0` |
| `0xBF` | 191 | `B839B220()` | `IL_32F9` |
| `0xC0` | 192 | `A302862D()` | `IL_3335` |
| `0xC1` | 193 | `'7A15E31B'()` | `IL_3371` |
| `0xC2` | 194 | `BD3588B7()` | `IL_33B9` |
| `0xC3` | 195 | `B1190689()` | `IL_340B` |
| `0xC4` | 196 | `'76862C12'()` | `IL_3459` |
| `0xC5` | 197 | `D3052B17()` | `IL_3497` |
| `0xC6` | 198 | `'879D4733'()` | `IL_34C3` |
| `0xC7` | 199 | `C9BF0D8B()` | `IL_3504` |
| `0xC8` | 200 | `'4935572B'()` | `IL_3552` |
| `0xC9` | 201 | `'1C922035'()` | `IL_35B2` |
| `0xCA` | 202 | `AF908ABB()` | `IL_35F4` |
| `0xCB` | 203 | `DBA84833()` | `IL_3636` |
| `0xCC` | 204 | `B59103A5()` | `IL_366C` |
| `0xCD` | 205 | `'86043CA7'()` | `IL_36BE` |
| `0xCE` | 206 | `'1D3F64BC'()` | `IL_36EF` |
| `0xCF` | 207 | `E82B3785()` | `IL_373E` |
| `0xD0` | 208 | `'9D21EEA9'()` | `IL_3794` |
| `0xD1` | 209 | `B839B220()` | `IL_37E2` |
| `0xD2` | 210 | `A1A14C36()` | `IL_3831` |
| `0xD3` | 211 | `'89A2E63B'()` | `IL_385F` |
| `0xD4` | 212 | `FC0F1D31()` | `IL_38B5` |
| `0xD5` | 213 | `FC0F1D31()` | `IL_38EE` |
| `0xD6` | 214 | `'74B39F1C'()` | `IL_393A` |
| `0xD7` | 215 | `CD3F76B2()` | `IL_398B` |
| `0xD8` | 216 | `BA870B21()` | `IL_39D4` |
| `0xD9` | 217 | `'7326F70C'()` | `IL_3A1A` |
| `0xDA` | 218 | `A1A14C36()` | `IL_3A58` |
| `0xDB` | 219 | `'879D4733'()` | `IL_3A90` |
| `0xDC` | 220 | `D9B2E438()` | `IL_3ABE` |
| `0xDD` | 221 | `'91AF9321'()` | `IL_3B02` |
| `0xDE` | 222 | `'4435311D'()` | `IL_3B43` |
| `0xDF` | 223 | `'7106D89C'()` | `IL_3B85` |
| `0xE0` | 224 | `'5931DC83'()` | `IL_3BCF` |
| `0xE1` | 225 | `'3BAD442A'()` | `IL_3C0F` |
| `0xE2` | 226 | `'74B39F1C'()` | `IL_3C67` |
| `0xE3` | 227 | `'76862C12'()` | `IL_3CAD` |
| `0xE4` | 228 | `E82B3785()` | `IL_3CEE` |
| `0xE5` | 229 | `B839B220()` | `IL_3D30` |
| `0xE6` | 230 | `D9B2E438()` | `IL_3D66` |
| `0xE7` | 231 | `BD3588B7()` | `IL_3DA7` |
| `0xE8` | 232 | `'9C1EF127'()` | `IL_3DF5` |
| `0xE9` | 233 | `BD3588B7()` | `IL_3E23` |
| `0xEA` | 234 | `'35A1509D'()` | `IL_3E65` |
| `0xEB` | 235 | `A1A14C36()` | `IL_3EA5` |
| `0xEC` | 236 | `'9DB004B4'()` | `IL_3EFB` |
| `0xED` | 237 | `CD3F76B2()` | `IL_3F31` |
| `0xEE` | 238 | `AF093527()` | `IL_3F83` |
| `0xEF` | 239 | `AF093527()` | `IL_3FC4` |
| `0xF0` | 240 | `'1C922035'()` | `IL_400B` |
| `0xF1` | 241 | `'71BAFF88'()` | `IL_4059` |
| `0xF2` | 242 | `'3EB2FA2F'()` | `IL_4097` |
| `0xF3` | 243 | `'9D21EEA9'()` | `IL_40E7` |
| `0xF4` | 244 | `'6CB9379B'()` | `IL_4139` |
| `0xF5` | 245 | `'6BBB0B8D'()` | `IL_4172` |
| `0xF6` | 246 | `A1A14C36()` | `IL_41B4` |
| `0xF7` | 247 | `'9D21EEA9'()` | `IL_41F6` |
| `0xF8` | 248 | `'64A9A13F'()` | `IL_4234` |
| `0xF9` | 249 | `B59103A5()` | `IL_4275` |
| `0xFA` | 250 | `CD970A3D()` | `IL_42BB` |
| `0xFB` | 251 | `D3052B17()` | `IL_430A` |
| `0xFC` | 252 | `'14B8FDA4'()` | `IL_4354` |
| `0xFD` | 253 | `'513EF216'()` | `IL_438A` |
| `0xFE` | 254 | `B59103A5()` | `IL_43E1` |
| `0xFF` | 255 | `BD3588B7()` | `IL_4417` |

## 14. Appendix B — All 93 distinct callback methods and aliases

The **category** is only a source-level direct-call or heuristic category. It does not prove an application's purpose or runtime reachability. The associated machine-readable callback CSV preserves the complete signature, direct internal/external targets, IL op frequencies, fields, literals and conservative assessment.

| MethodDef | Handler | Opcode aliases | Registration count | IL instructions | Static category |
|---|---|---|---:|---:|---|
| `0x0600027B` | `7026BDB3` |  | 1 | 39 | internal helper calls |
| `0x0600027C` | `DF3D6327` | 0x0D | 1 | 47 | internal helper calls |
| `0x0600027D` | `FBA6060E` | 0x2B, 0x75 | 2 | 45 | internal helper calls |
| `0x0600027E` | `4435311D` |  | 2 | 29 | internal helper calls |
| `0x0600027F` | `6BBB0B8D` |  | 3 | 149 | runtime type inspection; throws |
| `0x06000280` | `B1A9FC34` | 0x32 | 1 | 48 | internal helper calls |
| `0x06000282` | `800AB499` |  | 2 | 55 | other external API interaction; throws |
| `0x06000283` | `3BAD442A` |  | 3 | 110 | runtime type inspection; throws |
| `0x06000284` | `3C806315` |  | 2 | 22 | internal helper calls |
| `0x06000285` | `4935572B` |  | 3 | 342 | other external API interaction; writes field |
| `0x06000286` | `1A100412` |  | 2 | 10 | internal helper calls |
| `0x06000287` | `FC0F1D31` | 0x26, 0x73, 0x97, 0xAA, 0xB8, 0xD4, 0xD5 | 7 | 199 | reflection or dynamic-code API interaction |
| `0x06000288` | `05B08081` |  | 2 | 37 | internal helper calls |
| `0x06000289` | `7106D89C` |  | 2 | 32 | other external API interaction; throws |
| `0x0600028A` | `549EC905` |  | 1 | 19 | internal helper calls |
| `0x0600028B` | `85040E1F` |  | 4 | 44 | internal helper calls |
| `0x0600028C` | `1B9A0FA8` |  | 1 | 43 | internal helper calls |
| `0x0600028E` | `1C922035` |  | 4 | 37 | internal helper calls |
| `0x0600028F` | `A70C929E` | 0x0B, 0x52 | 2 | 51 | internal helper calls |
| `0x06000290` | `5931DC83` |  | 6 | 39 | internal helper calls |
| `0x06000292` | `478FD68B` |  | 1 | 63 | internal helper calls |
| `0x06000293` | `6D996612` |  | 1 | 32 | internal helper calls |
| `0x06000294` | `A12F070C` | 0x09 | 1 | 55 | internal helper calls |
| `0x06000295` | `8B1A351C` |  | 2 | 49 | internal helper calls |
| `0x06000296` | `D719AC25` | 0x1A | 1 | 53 | internal helper calls |
| `0x06000297` | `5D26C703` |  | 1 | 50 | internal helper calls |
| `0x06000298` | `21803F9F` |  | 5 | 24 | internal helper calls |
| `0x0600029A` | `3526928B` |  | 1 | 190 | other external API interaction; throws |
| `0x0600029B` | `B51FB5B5` | 0x4E | 1 | 52 | internal helper calls |
| `0x0600029C` | `918908BF` |  | 1 | 457 | runtime type inspection; throws |
| `0x0600029D` | `B1190689` | 0x01, 0xC3 | 2 | 29 | internal helper calls |
| `0x0600029E` | `7603EE86` |  | 1 | 51 | internal helper calls |
| `0x0600029F` | `AF093527` | 0x00, 0x8B, 0x8C, 0xEE, 0xEF | 5 | 59 | internal helper calls |
| `0x060002A0` | `7326F70C` |  | 2 | 743 | reflection or dynamic-code API interaction; throws |
| `0x060002A1` | `8C379AB2` |  | 5 | 82 | internal helper calls |
| `0x060002A2` | `99BED52B` |  | 2 | 71 | other external API interaction; throws |
| `0x060002A3` | `BD3588B7` | 0x1F, 0x6C, 0x87, 0x9A, 0x9E, 0xC2, 0xE7, 0xE9, 0xFF | 9 | 24 | internal helper calls |
| `0x060002A4` | `513EF216` |  | 4 | 352 | reflection or dynamic-code API interaction |
| `0x060002A5` | `AFA5D200` | 0x15 | 1 | 56 | internal helper calls |
| `0x060002A6` | `C7154D83` | 0x0E | 1 | 54 | internal helper calls |
| `0x060002A7` | `CD3F76B2` | 0x07, 0x42, 0xD7, 0xED | 4 | 43 | internal helper calls |
| `0x060002A8` | `019272A0` |  | 1 | 30 | internal helper calls |
| `0x060002A9` | `1C856C10` |  | 1 | 156 | runtime type inspection |
| `0x060002AA` | `91AF9321` |  | 2 | 24 | internal helper calls |
| `0x060002AD` | `AF908ABB` | 0x18, 0x6F, 0x7F, 0xCA | 4 | 50 | internal helper calls |
| `0x060002AE` | `35A1509D` |  | 2 | 49 | internal helper calls |
| `0x060002AF` | `879D4733` |  | 4 | 88 | runtime type inspection |
| `0x060002B0` | `22B83F93` |  | 2 | 2181 | reflection or dynamic-code API interaction; throws |
| `0x060002B1` | `5EA8F02F` |  | 1 | 152 | reflection or dynamic-code API interaction; throws |
| `0x060002B2` | `D9B2E438` | 0x3C, 0xDC, 0xE6 | 3 | 87 | internal helper calls; writes field |
| `0x060002B3` | `AE967FAB` | 0x3A, 0xA6 | 2 | 37 | internal helper calls |
| `0x060002B5` | `79AF42A2` |  | 1 | 58 | other external API interaction |
| `0x060002B6` | `CEB29D2C` | 0x36 | 1 | 61 | internal helper calls |
| `0x060002B7` | `4F2680A8` |  | 1 | 52 | internal helper calls |
| `0x060002B8` | `C9BF0D8B` | 0x24, 0xC7 | 2 | 45 | internal helper calls |
| `0x060002B9` | `EB2248B9` | 0x41, 0x92 | 2 | 53 | internal helper calls |
| `0x060002BB` | `792359AC` |  | 1 | 49 | internal helper calls |
| `0x060002BC` | `B839B220` | 0x20, 0x8A, 0x9D, 0xB1, 0xB3, 0xBF, 0xD1, 0xE5 | 8 | 42 | internal helper calls |
| `0x060002BD` | `76862C12` |  | 6 | 182 | runtime type inspection |
| `0x060002BE` | `3EB2FA2F` |  | 3 | 24 | internal helper calls |
| `0x060002BF` | `34B71D07` |  | 6 | 51 | internal helper calls |
| `0x060002C0` | `8C26AAA4` |  | 1 | 25 | single internal helper call |
| `0x060002C2` | `6CB9379B` |  | 4 | 25 | internal helper calls |
| `0x060002C3` | `C5931FB9` | 0x3E, 0x95 | 2 | 112 | other external API interaction; throws |
| `0x060002C4` | `21026DA1` |  | 2 | 49 | internal helper calls |
| `0x060002C5` | `AE2F9A26` | 0x27 | 1 | 27 | internal helper calls |
| `0x060002C6` | `D1934D8B` | 0x57 | 1 | 32 | internal helper calls |
| `0x060002C7` | `E82B3785` | 0x40, 0xCF, 0xE4 | 3 | 88 | internal helper calls |
| `0x060002C8` | `9DB004B4` |  | 3 | 12 | other external API interaction; throws |
| `0x060002C9` | `64A9A13F` |  | 2 | 36 | internal helper calls |
| `0x060002CA` | `50080737` |  | 2 | 44 | internal helper calls |
| `0x060002CB` | `14B8FDA4` |  | 2 | 63 | other external API interaction; throws |
| `0x060002CC` | `B0964A39` | 0x28 | 1 | 20 | internal helper calls |
| `0x060002CD` | `C983FEBF` | 0x2E | 1 | 58 | internal helper calls |
| `0x060002CE` | `74B39F1C` |  | 7 | 361 | reflection or dynamic-code API interaction |
| `0x060002CF` | `BA870B21` | 0x14, 0xD8 | 2 | 45 | internal helper calls |
| `0x060002D0` | `D3052B17` | 0x06, 0xC5, 0xFB | 3 | 54 | internal helper calls |
| `0x060002D1` | `A302862D` | 0x34, 0x80, 0xC0 | 3 | 32 | internal helper calls |
| `0x060002D2` | `B59103A5` | 0x02, 0x61, 0x65, 0x6D, 0x6E, 0xCC, 0xF9, 0xFE | 8 | 44 | internal helper calls |
| `0x060002D3` | `86043CA7` |  | 3 | 10 | internal helper calls |
| `0x060002D4` | `89A2E63B` |  | 3 | 58 | internal helper calls |
| `0x060002D5` | `1101EC8C` |  | 1 | 67 | runtime/memory API interaction |
| `0x060002D6` | `B40B1435` | 0x10 | 1 | 30 | internal helper calls |
| `0x060002D7` | `9C1EF127` |  | 2 | 40 | internal helper calls |
| `0x060002D8` | `A1A14C36` | 0x0C, 0x72, 0x88, 0x89, 0xA1, 0xA4, 0xAB, 0xB5, 0xD2, 0xDA, 0xEB, 0xF6 | 12 | 64 | internal helper calls |
| `0x060002D9` | `CD970A3D` | 0x4A, 0xFA | 2 | 28 | internal helper calls |
| `0x060002DA` | `7A15E31B` |  | 2 | 54 | internal helper calls |
| `0x060002DB` | `DBA84833` | 0x2F, 0x67, 0x96, 0xA9, 0xCB | 5 | 52 | internal helper calls |
| `0x060002DC` | `71BAFF88` |  | 2 | 29 | internal helper calls |
| `0x060002DD` | `6D36168F` |  | 2 | 49 | internal helper calls |
| `0x060002DE` | `BC0FF3AE` | 0x3B, 0x7B, 0x84, 0xA5 | 4 | 16 | internal helper calls |
| `0x060002DF` | `1D3F64BC` |  | 3 | 55 | internal helper calls |
| `0x060002E2` | `9D21EEA9` |  | 11 | 35 | internal helper calls |

## 15. Appendix C — All 124 statically decoded typed VM local slots

The entry's type token, declared type-name resolution and selected opcode alias come from the preserved reader-state reconstruction. "TypeSpec not resolved" / "TypeDef unresolved" means signature/name recovery was not established; no type has been invented.

| Slot | Start RVA | Value opcode | Type token | Resolved type | Store opcode |
|---:|---|---|---|---|---|
| 0 | `0x0080050B` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 1 | `0x008004F9` | `0xC3` | `0x01000058` | System.UInt32 | `0xC4` |
| 2 | `0x008004E7` | `0x01` | `0x1B000021` | TypeSpec (not resolved) | `0xE3` |
| 3 | `0x008004D5` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 4 | `0x008004C3` | `0x01` | `0x1B000020` | TypeSpec (not resolved) | `0x70` |
| 5 | `0x008004B1` | `0xC3` | `0x01000081` | System.Reflection.Emit.DynamicMethod | `0x77` |
| 6 | `0x0080049F` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 7 | `0x0080048D` | `0xC3` | `0x01000057` | System.Int32 | `0xC4` |
| 8 | `0x0080047B` | `0x01` | `0x01000058` | System.UInt32 | `0xE3` |
| 9 | `0x00800469` | `0xC3` | `0x02000080` | TypeDef (not resolved) | `0x54` |
| 10 | `0x00800457` | `0x01` | `0x01000058` | System.UInt32 | `0x70` |
| 11 | `0x00800445` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 12 | `0x00800433` | `0x01` | `0x0100005A` | System.UInt16 | `0xA8` |
| 13 | `0x00800421` | `0xC3` | `0x01000058` | System.UInt32 | `0xC4` |
| 14 | `0x0080040F` | `0x01` | `0x01000057` | System.Int32 | `0xE3` |
| 15 | `0x008003FD` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 16 | `0x008003EB` | `0x01` | `0x02000080` | TypeDef (not resolved) | `0x70` |
| 17 | `0x008003D9` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 18 | `0x008003C7` | `0x01` | `0x010000BB` | System.Int64 | `0xA8` |
| 19 | `0x008003B5` | `0xC3` | `0x01000082` | System.Reflection.Emit.DynamicILInfo | `0xC4` |
| 20 | `0x008003A3` | `0x01` | `0x1B000026` | TypeSpec (not resolved) | `0xE3` |
| 21 | `0x00800391` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 22 | `0x0080037F` | `0x01` | `0x01000058` | System.UInt32 | `0x70` |
| 23 | `0x0080036D` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 24 | `0x0080035B` | `0x01` | `0x1B000021` | TypeSpec (not resolved) | `0xA8` |
| 25 | `0x00800349` | `0xC3` | `0x01000058` | System.UInt32 | `0xC4` |
| 26 | `0x00800337` | `0x01` | `0x0100007D` | System.Reflection.MethodBase | `0xE3` |
| 27 | `0x00800325` | `0xC3` | `0x01000028` | System.Type | `0x54` |
| 28 | `0x00800313` | `0x01` | `0x01000058` | System.UInt32 | `0x70` |
| 29 | `0x00800301` | `0xC3` | `0x010000BB` | System.Int64 | `0x77` |
| 30 | `0x008002EF` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 31 | `0x008002DD` | `0xC3` | `0x010000BB` | System.Int64 | `0xC4` |
| 32 | `0x008002CB` | `0x01` | `0x010000BA` | System.Int16 | `0xE3` |
| 33 | `0x008002B9` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 34 | `0x008002A7` | `0x01` | `0x1B000006` | TypeSpec (not resolved) | `0x70` |
| 35 | `0x00800295` | `0xC3` | `0x01000091` | System.IntPtr | `0x77` |
| 36 | `0x00800283` | `0x01` | `0x01000057` | System.Int32 | `0xA8` |
| 37 | `0x00800271` | `0xC3` | `0x0100005A` | System.UInt16 | `0xC4` |
| 38 | `0x0080025F` | `0x01` | `0x0200003E` | TypeDef (not resolved) | `0xE3` |
| 39 | `0x0080024D` | `0xC3` | `0x0100007F` | System.Reflection.MethodInfo | `0x54` |
| 40 | `0x0080023B` | `0x01` | `0x1B000021` | TypeSpec (not resolved) | `0x70` |
| 41 | `0x00800229` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 42 | `0x00800217` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 43 | `0x00800205` | `0xC3` | `0x01000091` | System.IntPtr | `0xC4` |
| 44 | `0x008001F3` | `0x01` | `0x1B000006` | TypeSpec (not resolved) | `0xE3` |
| 45 | `0x008001E1` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 46 | `0x008001CF` | `0x01` | `0x01000057` | System.Int32 | `0x70` |
| 47 | `0x008001BD` | `0xC3` | `0x1B00000A` | TypeSpec (not resolved) | `0x77` |
| 48 | `0x008001AB` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 49 | `0x00800199` | `0xC3` | `0x01000057` | System.Int32 | `0xC4` |
| 50 | `0x00800187` | `0x01` | `0x010000BB` | System.Int64 | `0xE3` |
| 51 | `0x00800175` | `0xC3` | `0x02000080` | TypeDef (not resolved) | `0x54` |
| 52 | `0x00800163` | `0x01` | `0x010000BB` | System.Int64 | `0x70` |
| 53 | `0x00800151` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 54 | `0x0080013F` | `0x01` | `0x01000057` | System.Int32 | `0xA8` |
| 55 | `0x0080012D` | `0xC3` | `0x1B000021` | TypeSpec (not resolved) | `0xC4` |
| 56 | `0x0080011B` | `0x01` | `0x01000058` | System.UInt32 | `0xE3` |
| 57 | `0x00800109` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 58 | `0x008000F7` | `0x01` | `0x01000058` | System.UInt32 | `0x70` |
| 59 | `0x008000E5` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 60 | `0x008000D3` | `0x01` | `0x1B000006` | TypeSpec (not resolved) | `0xA8` |
| 61 | `0x008000C1` | `0xC3` | `0x1B000021` | TypeSpec (not resolved) | `0xC4` |
| 62 | `0x008000AF` | `0x01` | `0x01000058` | System.UInt32 | `0xE3` |
| 63 | `0x0080009D` | `0xC3` | `0x0100007E` | System.Reflection.FieldInfo | `0x54` |
| 64 | `0x0080008B` | `0x01` | `0x01000058` | System.UInt32 | `0x70` |
| 65 | `0x00800079` | `0xC3` | `0x01000059` | System.Boolean | `0x77` |
| 66 | `0x00800067` | `0x01` | `0x01000057` | System.Int32 | `0xA8` |
| 67 | `0x00800055` | `0xC3` | `0x01000058` | System.UInt32 | `0xC4` |
| 68 | `0x00800043` | `0x01` | `0x01000091` | System.IntPtr | `0xE3` |
| 69 | `0x00800031` | `0xC3` | `0x1B000027` | TypeSpec (not resolved) | `0x54` |
| 70 | `0x0080001F` | `0x01` | `0x01000058` | System.UInt32 | `0x70` |
| 71 | `0x0080000D` | `0xC3` | `0x010000BA` | System.Int16 | `0x77` |
| 72 | `0x007FFFFB` | `0x01` | `0x1B000006` | TypeSpec (not resolved) | `0xA8` |
| 73 | `0x007FFFE9` | `0xC3` | `0x01000058` | System.UInt32 | `0xC4` |
| 74 | `0x007FFFD7` | `0x01` | `0x0200003E` | TypeDef (not resolved) | `0xE3` |
| 75 | `0x007FFFC5` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 76 | `0x007FFFB3` | `0x01` | `0x01000057` | System.Int32 | `0x70` |
| 77 | `0x007FFFA1` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 78 | `0x007FFF8F` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 79 | `0x007FFF7D` | `0xC3` | `0x01000058` | System.UInt32 | `0xC4` |
| 80 | `0x007FFF6B` | `0x01` | `0x0100001C` | System.Object | `0xE3` |
| 81 | `0x007FFF59` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 82 | `0x007FFF47` | `0x01` | `0x1B000020` | TypeSpec (not resolved) | `0x70` |
| 83 | `0x007FFF35` | `0xC3` | `0x01000059` | System.Boolean | `0x77` |
| 84 | `0x007FFF23` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 85 | `0x007FFF11` | `0xC3` | `0x01000028` | System.Type | `0xC4` |
| 86 | `0x007FFEFF` | `0x01` | `0x02000080` | TypeDef (not resolved) | `0xE3` |
| 87 | `0x007FFEED` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 88 | `0x007FFEDB` | `0x01` | `0x01000038` | System.String | `0x70` |
| 89 | `0x007FFEC9` | `0xC3` | `0x1B000021` | TypeSpec (not resolved) | `0x77` |
| 90 | `0x007FFEB7` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 91 | `0x007FFEA5` | `0xC3` | `0x01000058` | System.UInt32 | `0xC4` |
| 92 | `0x007FFE93` | `0x01` | `0x01000058` | System.UInt32 | `0xE3` |
| 93 | `0x007FFE81` | `0xC3` | `0x01000057` | System.Int32 | `0x54` |
| 94 | `0x007FFE6F` | `0x01` | `0x1B000023` | TypeSpec (not resolved) | `0x70` |
| 95 | `0x007FFE5D` | `0xC3` | `0x1B000028` | TypeSpec (not resolved) | `0x77` |
| 96 | `0x007FFE4B` | `0x01` | `0x01000097` | System.UIntPtr | `0xA8` |
| 97 | `0x007FFE39` | `0xC3` | `0x01000057` | System.Int32 | `0xC4` |
| 98 | `0x007FFE27` | `0x01` | `0x1B000022` | TypeSpec (not resolved) | `0xE3` |
| 99 | `0x007FFE15` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |
| 100 | `0x007FFE03` | `0x01` | `0x01000058` | System.UInt32 | `0x70` |
| 101 | `0x007FFDF1` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 102 | `0x007FFDDF` | `0x01` | `0x0100007C` | System.Reflection.Module | `0xA8` |
| 103 | `0x007FFDCD` | `0xC3` | `0x01000058` | System.UInt32 | `0xC4` |
| 104 | `0x007FFDBB` | `0x01` | `0x1B000006` | TypeSpec (not resolved) | `0xE3` |
| 105 | `0x007FFDA9` | `0xC3` | `0x1B000021` | TypeSpec (not resolved) | `0x54` |
| 106 | `0x007FFD97` | `0x01` | `0x01000058` | System.UInt32 | `0x70` |
| 107 | `0x007FFD85` | `0xC3` | `0x1B000006` | TypeSpec (not resolved) | `0x77` |
| 108 | `0x007FFD73` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 109 | `0x007FFD61` | `0xC3` | `0x1B000006` | TypeSpec (not resolved) | `0xC4` |
| 110 | `0x007FFD4F` | `0x01` | `0x01000058` | System.UInt32 | `0xE3` |
| 111 | `0x007FFD3D` | `0xC3` | `0x01000059` | System.Boolean | `0x54` |
| 112 | `0x007FFD2B` | `0x01` | `0x01000058` | System.UInt32 | `0x70` |
| 113 | `0x007FFD19` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 114 | `0x007FFD07` | `0x01` | `0x01000091` | System.IntPtr | `0xA8` |
| 115 | `0x007FFCF5` | `0xC3` | `0x01000058` | System.UInt32 | `0xC4` |
| 116 | `0x007FFCE3` | `0x01` | `0x01000059` | System.Boolean | `0xE3` |
| 117 | `0x007FFCD1` | `0xC3` | `0x01000057` | System.Int32 | `0x54` |
| 118 | `0x007FFCBF` | `0x01` | `0x0200003E` | TypeDef (not resolved) | `0x70` |
| 119 | `0x007FFCAD` | `0xC3` | `0x01000058` | System.UInt32 | `0x77` |
| 120 | `0x007FFC9B` | `0x01` | `0x01000058` | System.UInt32 | `0xA8` |
| 121 | `0x007FFC89` | `0xC3` | `0x01000057` | System.Int32 | `0xC4` |
| 122 | `0x007FFC77` | `0x01` | `0x01000057` | System.Int32 | `0xE3` |
| 123 | `0x007FFC65` | `0xC3` | `0x01000058` | System.UInt32 | `0x54` |

## 16. Appendix D — All 43 final offline reader-decoding evidence records

These records are *the script's statically decoded stream*, not captured dynamic operations. The last record of each block may be a cursor-changing operation, so the next physical byte cannot be linearly decoded without updating state.

| Stream | Cursor before | Read | Decoded value | Handler | Analyst description |
|---|---|---|---|---|---|
| 76B7C6BB .cctor | `0x007FC7AF` | opcode | `0x00000010` | `B40B1435()` | push uint32 |
| 76B7C6BB .cctor | `0x007FC7AE` | u32 | `0x00000000` | `` | integer 0 |
| 76B7C6BB .cctor | `0x007FC7AA` | opcode | `0x00000050` | `'8C26AAA4'()` | stack discard |
| 76B7C6BB .cctor | `0x007FC7A9` | opcode | `0x00000050` | `'8C26AAA4'()` | stack discard |
| 76B7C6BB .cctor | `0x007FC7A8` | opcode | `0x00000010` | `B40B1435()` | push uint32 |
| 76B7C6BB .cctor | `0x007FC7A7` | u32 | `0x00000034` | `` | array length 52 |
| 76B7C6BB .cctor | `0x007FC7A3` | opcode | `0x0000001B` | `'79AF42A2'()` | allocate typed array |
| 76B7C6BB .cctor | `0x007FC7A2` | u32 | `0x01000058` | `` | System.UInt32 |
| 76B7C6BB .cctor | `0x007FC79E` | opcode | `0x00000001` | `B1190689()` | resolve VM value |
| 76B7C6BB .cctor | `0x007FC79D` | u32 | `0x00000000` | `` | value 0 |
| 76B7C6BB .cctor | `0x007FC799` | opcode | `0x00000012` | `'35A1509D'()` | field reference |
| 76B7C6BB .cctor | `0x007FC798` | u32 | `0x04000182` | `` | 76B7C6BB.D0244F83 (static UInt32[]) |
| 76B7C6BB .cctor | `0x007FC794` | opcode | `0x0000001A` | `D719AC25()` | typed assignment |
| 76B7C6BB .cctor | `0x007FC793` | opcode | `0x000000C3` | `B1190689()` | resolve VM value |
| 76B7C6BB .cctor | `0x007FC792` | u32 | `0x00000000` | `` | value 0 |
| 76B7C6BB .cctor | `0x007FC78E` | opcode | `0x00000010` | `B40B1435()` | push uint32 |
| 76B7C6BB .cctor | `0x007FC78D` | u32 | `0x00000000` | `` | integer 0 |
| 76B7C6BB .cctor | `0x007FC789` | opcode | `0x00000039` | `'7026BDB3'()` | wrapped cursor field reference |
| 76B7C6BB .cctor | `0x007FC788` | u32 | `0x04000191` | `` | 6633B699.B32A609B (A3B21017 reader) |
| 76B7C6BB .cctor | `0x007FC784` | opcode | `0x0000001A` | `D719AC25()` | typed assignment / possible cursor redirection |
| second nested | `0x007FE224` | u16 | `0x00000000` | `` | header count |
| second nested | `0x007FE222` | u32 | `0x01000058` | `` | System.UInt32 |
| second nested | `0x007FE21E` | u32 | `0x01000066` | `` | System.Enum |
| second nested | `0x007FE21A` | opcode | `0x00000010` | `B40B1435()` | push |
| second nested | `0x007FE219` | u32 | `0x00000000` | `` | zero |
| second nested | `0x007FE215` | opcode | `0x00000050` | `'8C26AAA4'()` | discard |
| second nested | `0x007FE214` | opcode | `0x00000050` | `'8C26AAA4'()` | discard |
| second nested | `0x007FE213` | opcode | `0x000000C3` | `B1190689()` | resolve VM value |
| second nested | `0x007FE212` | u32 | `0x00000000` | `` | zero |
| second nested | `0x007FE20E` | opcode | `0x00000012` | `'35A1509D'()` | field ref |
| second nested | `0x007FE20D` | u32 | `0x04000182` | `` | static uint[] |
| second nested | `0x007FE209` | opcode | `0x0000000D` | `DF3D6327()` | convert |
| second nested | `0x007FE208` | opcode | `0x00000010` | `B40B1435()` | push |
| second nested | `0x007FE207` | u32 | `0x00000005` | `` | array index |
| second nested | `0x007FE203` | opcode | `0x00000095` | `C5931FB9()` | array get |
| second nested | `0x007FE202` | u32 | `0x01000058` | `` | UInt32 |
| second nested | `0x007FE1FE` | opcode | `0x00000024` | `C9BF0D8B()` | convert |
| second nested | `0x007FE1FD` | u32 | `0x01000058` | `` | UInt32 |
| second nested | `0x007FE1F9` | opcode | `0x00000010` | `B40B1435()` | push |
| second nested | `0x007FE1F8` | u32 | `0x00000000` | `` | zero |
| second nested | `0x007FE1F4` | opcode | `0x00000039` | `'7026BDB3'()` | cursor field wrapper |
| second nested | `0x007FE1F3` | u32 | `0x04000191` | `` | reader |
| second nested | `0x007FE1EF` | opcode | `0x0000001A` | `D719AC25()` | typed assignment / possible cursor redirection |

## 17. Appendix E — Verified ancillary evidence inventory and how to use it

The master package contains the exact *full* CSV / JSON / disassembly files rather than truncating them to fit page layouts. **Archive members and content counts were audited directly**: 888-row method CSV, 650 IL method headers, 650 CFG entries with 2,725 blocks and 3,348 edges, and 2,561 call edges. Eight UTF-16 IL/C# source exports have been normalized to UTF-8 in this revised archive. Each is an independent evidentiary dimension:

| Source file | Scope / purpose |
|---|---|
| `SjTNlCHNfW_recovery_status.csv` | All 888 MethodDefs, RVA/backing/decode/block/call counts |
| `SjTNlCHNfW_function_inventory.csv` | All 888 method metadata rows and initial file bytes |
| `SjTNlCHNfW_pass6_method_provenance.csv` | Independent metadata/section backing audit |
| `SjTNlCHNfW_disassembly.il.txt` | All 650 file-backed bodies, decoded IL instructions |
| `SjTNlCHNfW_cleaned_il_view.txt` | Conservative simplified IL for supported patterns |
| `SjTNlCHNfW_control_flow_graphs.json` | Basic-block nodes and graph edges |
| `SjTNlCHNfW_call_edges.csv` | Full 2,561 syntactic call-reference edges |
| `SjTNlCHNfW_recovered_methods.csv` | Structural metrics for decoded methods |
| `SjTNlCHNfW_candidate_method_behaviors.csv` | 71 conservative helper classifications, not source truth |
| `vm_constructor_full.il.txt` | Complete 17,437-byte IL constructor printout |
| `vm_opcode_map.csv` | All 256 opcode keys and handler registration sites |
| `SjTNlCHNfW_registration_sites.csv` | 256 delegate registration call sites and MethodDefs |
| `SjTNlCHNfW_registration_targets.csv` | Registration target summary |
| `SjTNlCHNfW_93_callback_semantic_inventory.csv` | All 93 callbacks, signatures, direct targets, IL operations, fields |
| `SjTNlCHNfW_callback_helper_edges.csv` | Direct callback→helper relations |
| `SjTNlCHNfW_pass6_helper_method_audit.csv` | 161 VM/helper type method metadata rows |
| `SjTNlCHNfW_verified_vm_trace.csv` | Original root and first-nested decode |
| `SjTNlCHNfW_recovered_nested_local_init.csv` | Complete repeated-local decoder output |
| `SjTNlCHNfW_verified_124_local_slots.csv` | Slots and type-token data before name enrichment |
| `SjTNlCHNfW_typed_124_local_slots.csv` | All 124 local types and RVAs |
| `SjTNlCHNfW_second_nested_trace.csv` | Reader operations until the second reader reset |
| `SjTNlCHNfW_assignment_boundary.csv` | Conditional stale-reader 0x9C path, *not executed* |
| `SjTNlCHNfW_new_reader_jump_evidence.csv` | 43 latest reader records from two protected streams |
| `helper_32bit.cs.txt`, `helper_64bit.cs.txt` | Decompiled 32/64-bit numeric value implementations |
| `opcode_00.il.txt`, `opcode_01.il.txt`, `opcode_02.il.txt` | Original handler IL of early observed methods |
| `opcode_01_helper.cs.txt`, `opcode_02_helper.cs.txt` | Comparison and left-shift arithmetic helper output |
| `Recovery-Step5.zip` … `Recovery-Step10.zip` | Previous metadata/reader exports and recovery evidence |
| `static_reader_emulator.py`, `recover_vm_nested_locals.py`, `verify_reader_jump.py` | Reproducible offline instruction reader / trace validation |
| `analyze_vm_constructor.py`, `enrich_vm_type_tokens.py` | Registration-key and metadata type enrichment |
| Historical `SjTNlCHNfW_*.md` reports | Chronological reasoning record, including superseded hypotheses |

**Scope reminder:** This is a **loader + protector analysis**, not an analysis of aimbot/ESP functionality. The existence, implementation, and use of any cheat feature remain unverified.

**Open questions (each unresolved, not omitted):** What populates the 163 virtual-only IL method ranges, and when? Which of those methods are ever invoked? What are all successful runtime branches of the VM's arithmetic obfuscation? What is `D0244F83[5]` after initialization? Are its remaining 51 elements jump targets and what values do they hold? Which methods are resolved by the protected payload and with what arguments? Which network domain is contacted, if any? What filesystem, registry, credential, or process interactions occur, if any? What inputs/keys/activation state are required? Is the sample malicious or merely licensed/obfuscated? How does its control flow terminate in practice? The current static artifacts do not answer these with evidence.

