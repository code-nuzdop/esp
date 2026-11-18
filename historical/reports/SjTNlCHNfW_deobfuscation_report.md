# SjTNlCHNfW.exe — static IL and control-flow recovery, pass 2

## Provenance
- Original SHA-256: `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`
- Original size: 6,783,488 bytes
- This analysis is static only: the executable was never run, loaded into the CLR, or patched.

## Findings and corrected interpretation of earlier analysis
- The assembly is a PE32 i386 .NET/CLR executable with 888 MethodDef entries.
- **650 methods** have file-backed, syntactically decodable IL streams. Their instruction sequences and branch destinations were parsed, yielding **2,725 basic blocks and 3,348 CFG edges**. This establishes structural recoverability, NOT necessarily meaningful or verifiable source-level semantics.
- **163 methods** declare RVA locations inside two PE sections with no raw file bytes: 107 previously called `invalid-header`, 23 previously called `invalid-fat`, and 33 previously called `tiny`. These are **not valid on-disk IL methods**. In particular, method 35 (token `0x06000023`, entry point) is virtual-only at RVA `0x2050`. The earlier report incorrectly treated bytes at some corresponding mapped offsets as candidate actual IL, even though the sections are unbacked.
- **75 methods** have RVA=0; these include metadata-only methods such as interface/delegate/abstract/runtime methods and do not prove encrypted IL.
- The two virtual-only sections are named `F!_~Pyan` (RVA `0x2000`, virtual size `0x3e26cc`, raw size 0) and `0[n6P0.A` (RVA `0x3e6000`, virtual size `0x40febb`, raw size 0). Their intended use remains unknown; runtime population is a plausible hypothesis, not a verified behavior.
- An ordinary file-backed CLR method body exists for `<Module>::.cctor` (token `0x06000001`, RVA `0x00A988D8`). The entire decoded method is:

```il
IL_0000: newobj 0x060002E3   // MethodDef 739, obfuscated .ctor
IL_0005: ldnull
IL_0006: ldc.i4 8365793
IL_000B: call   0x060002C1   // MethodDef 705, obfuscated method
IL_0010: pop
IL_0011: ret
```

This provides one concrete initialization dependency (constructor 739 -> method 705); it does NOT prove the precise meaning of either method or how the virtual sections may be populated. Execution paths into those methods depend on startup/initialization order and runtime semantics.

## Call graph
- **2,561** syntactic invocation references (`call`, `callvirt`, `newobj`, function pointers, `jmp`) in the 650 decodable bodies.
- **1,667** reference an in-assembly `MethodDef` token. Other references may be `MemberRef` (external or generic methods), etc.; these have not all been resolved to signatures.
- File `SjTNlCHNfW_call_edges.csv` contains caller tokens, IL offsets, invoked token and internal callee names where available. It is a static call-reference index, not a proof that every edge is reachable in execution.

## Control-flow recovery
- Branch targets and instruction boundaries were validated for the 650 file-backed methods using an ECMA-335 opcode decoder.
- File `SjTNlCHNfW_control_flow_graphs.json` contains method-level basic-block ranges and branch/fallthrough edges.
- File `SjTNlCHNfW_disassembly.il.txt` contains readable IL disassembly for all 650 recovered methods, with IL offsets and metadata tokens.
- Some decodable method bodies exhibit arithmetic-heavy obfuscation and opaque predicates, so structural CFG validity does not mean the graph represents feasible runtime paths. Stack verification, exception-region reconstruction, metadata resolution and constant propagation remain future work.

## What remains unknown
1. The missing entry point (`0x06000023`) and 162 other virtual-only methods cannot be decompiled from their declared on-disk RVAs.
2. The routine that creates, populates, or otherwise supplies these virtual sections at runtime has not been identified or observed. They might be protection artifacts, corrupted layout, loader-generated bodies or another mechanism.
3. Per-method behavioral names for all 650 valid-IL methods cannot be reliably assigned without type/member metadata resolution and semantic dataflow analysis.
4. The program has not been executed, therefore there is no runtime memory snapshot, trace, decrypted module, or proof that its observed static state runs correctly.

## Patch safety
- Do not patch virtual-only RVA methods or extrapolate their bytes from the file at those offsets.
- For file-backed methods, any proposed patch should be based on verified semantics and must preserve ECMA-335 IL stack balance, branch target layout, exception-handler regions and any assembly integrity checks.
- Without the missing startup code, byte-level edits to activation, protection, or initialization routines would be speculative; no modified executable has been produced.

## Outputs
1. `SjTNlCHNfW_recovery_status.csv`: all 888 methods, with actual file-backing and decoding status, CFG counts and inbound call-reference counts.
2. `SjTNlCHNfW_disassembly.il.txt`: decoded IL, instruction by instruction, for 650 file-backed methods.
3. `SjTNlCHNfW_control_flow_graphs.json`: structural CFG blocks and edges.
4. `SjTNlCHNfW_call_edges.csv`: static reference-level call graph.
5. `SjTNlCHNfW_recovered_methods.csv`: instruction and branch validation metrics for file-backed methods.

## Next analysis step
Static deobfuscation can proceed with type/member-ref resolution, constant folding, exception-region parsing and stack validation, but faithful recovery of the virtual-only entrypoint likely requires a trusted full memory snapshot from an isolated, instrumented runtime or a separately acquired unprotected build. Do not run this untrusted executable on a personal/work machine.
