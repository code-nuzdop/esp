# SjTNlCHNfW.exe — Pass 6 independent verification and remaining-evidence audit

## Scope and integrity
- Original binary inspected directly; no execution, mutation, memory capture, or external source artifacts.
- SHA-256: `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`.
- File size: 6,783,488 bytes.
- CLR MethodDef entries: 888; method inventory independently enumerated from metadata on this pass.

## Verified PE section backing
- `F!_~Pyan`: RVA `0x2000`, virtual size `0x3E26CC`, file offset `0x0`, raw size `0x0`.
- `0[n6P0.A`: RVA `0x3E6000`, virtual size `0x40FEBB`, file offset `0x0`, raw size `0x0`.
- `OVgPD_NR`: RVA `0x7F6000`, virtual size `0x8`, file offset `0x400`, raw size `0x200`.
- `_kh!cr6M`: RVA `0x7F8000`, virtual size `0x676AC8`, file offset `0x600`, raw size `0x676C00`.
- `PF.CT8VA`: RVA `0xE70000`, virtual size `0xDAB`, file offset `0x677200`, raw size `0xE00`.
- `:zqS2t{G`: RVA `0xE72000`, virtual size `0xC`, file offset `0x678000`, raw size `0x200`.

- Last raw section ends at file offset `6783488`; file length is `6783488`; **overlay bytes: 0**.
- Metadata root `BSJB` occurrence count: `1`. This rules out an obvious second full CLR metadata root, not embedded encrypted data.
- Method-body classifications by independently mapped section backing: {'file_backed': 650, 'no_RVA': 75, 'virtual_only': 163}.
- Decoded method entries from previous structural pass: 683. There is no proof all are runtime-reachable or semantically correct.
- `no_RVA` method implementation code-type bits: {3: 68, 0: 7}. No-RVA methods are not necessarily missing: interface, abstract, runtime-provided, and platform-invoked methods may not store IL.

## Directly verified .NET metadata
- Delegate TypeDef 27 (`95969DA2`) inherits from `System.MulticastDelegate` (as confirmed in pass 5).
- Its constructor MethodDef `0x06000082`: `(object, native int) -> void`; invoke MethodDef `0x06000081`: `() -> void`.
- The collection is a closed `Dictionary<uint32,95969DA2>` TypeSpec.
- MemberRef `0x0A00010C` is `set_Item` on that collection; `0x0A000152` is `get_Item`.
- Type `FB9C7B25` has 9 declared methods; type `8F0BF53C` has 29; type `A3B21017` has 14. Metadata names and signatures are recorded in the helper audit.
- Dispatch constructor `0x060002E3` and dispatcher `0x060002C1` have structurally decoded IL. Prior counts of 256 callback registration sites and 93 distinct callback targets remain **static** counts; this pass has not verified key reachability, callback invocation, or collisions during runtime.

## Statements that CANNOT honestly be upgraded to verified
1. **163 virtual-only method bodies:** the corresponding RVA ranges have no raw bytes in the original PE. Their instruction streams cannot be verified from this binary alone, even though the CLR metadata declares method RVAs. The entry-point token `0x06000023` is in this category.
2. **Complete source decompilation:** correct C# reconstruction needs method body bytes (or a validated assembly/runtime capture), exact exception handlers, recovered dynamic methods, and behavior tests. Structural instruction decoding alone does not meet this standard.
3. **Semantic labels for 93 callbacks:** all signatures and static direct references are measurable. Descriptions such as dynamic method generator, type conversion, allocator, and interpreter are partly inferred from API usage; actual runtime effects and reachability remain unverified.
4. **Decryption/runtime population mechanism:** no loader, key, or restoration routine has been dynamically observed. Zero overlay and zero raw size in two sections do NOT rule out payloads hidden inside mapped bytes or resources.
5. **Perfect patch locations:** these require the desired behavior, reachable call path, complete instructions, controlled test, and integrity-check results. No verified patch offsets have been established.

## Evidence needed to close the gaps
- A trusted, unprotected original build **or** an isolated reproducible runtime with complete captured CLR module memory, loader trace, runtime-generated dynamic methods, and a controlled input set.
- For runtime acquisition, use a disposable offline Windows VM snapshot (no personal credentials or connected production network), capture loaded module memory and CLR events **without blindly executing on a host computer**, retain hashes and exact timestamps, and compare captured IL to metadata signatures and IL stack validity.
- Next, reconstruct exception tables, cross-validate with independent disassemblers/decompilers, check control-flow paths using tests, and label each verified behavioral statement with input/output evidence.
- A developer should treat this as a **verified static structural audit with explicit unresolved runtime questions**, not a completed deobfuscation or perfect behavioral reproduction.

## Deliverables
- `SjTNlCHNfW_pass6_method_provenance.csv`: independently derived RVA/file-backing evidence for all 888 methods.
- `SjTNlCHNfW_pass6_helper_method_audit.csv`: signed method metadata and basic static call/branch metrics for the dispatcher, helper, and value-related types.
