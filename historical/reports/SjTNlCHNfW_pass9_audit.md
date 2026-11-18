# SjTNlCHNfW — Pass 9: C# extraction audit

## Provenance
Source: user-supplied `Recovery-Step9.zip` containing dnSpy.Console C# outputs for `0x060002EC`, `0x060002EB`, `0x060000D3`, `0x060000DB`, `0x060000D7`, and the `40AB99A9` class.

**Evidence grade:** static C# decompiler output, not executed or verified with test vectors. Original IL needed to disambiguate decompiler artifacts.

## Verified operations visible in C# output

- `40AB99A9` has a static `long` module-base field (`493E83B7`) and a static array of mapping records (`1F2D38B3`).
- `0x060002EC` calls `Marshal.GetHINSTANCE(typeof(B39F4A82).Module)` and stores `ToInt64()` in the module-base field. It checks `module.Assembly.Location.Length`, and contains a header/section parsing path with an allocation of `FE330A2A[]`. Branch reachability and all constants are **not** independently proven.
- `0x060002EB` accepts `uint`, checks mapping records, uses fields `B18168B8`, `01B8483A`, `7EB91C19`, and returns an `IntPtr` built by adding a resulting offset to the stored module base. A plausible mapping expression is `rawStart + (requested - virtualStart)`, conditional on the relevant range. It is **not yet equivalent to verified source**.
- `0x060000D7` assigns the input cast to `uint` to `D38A0391` and then copies that value into `78A03A01`, subject to branch simplification of obfuscated constants.
- `0x060000D3` performs an `ldind.u1`-equivalent memory byte read through the mapper, transforms the byte using `78A03A01`, and subsequently updates that state. The exact byte transformation is **not yet established**.
- `0x060000DB` performs an `ldind.u4`-equivalent memory read through the mapper and modifies the reader state. Its exact 32-bit transformation is **not yet established**.

## Decompiler limitations and correctness warnings

- `Reader_UInt32.cs.txt` contains an invalid C# expression, `uint num21 = obj >> num20;`, where `obj` is declared as `object`. The original IL is necessary to identify the actual operand type.
- `Mapper_Initialize.cs.txt` contains invalid C# pointer/ref constructs including `ref B39F4A82.FE330A2A ptr12 = (IntPtr)num12;`. Do **not** compile or patch using this output as-is.
- `Mapper_Resolve.cs.txt` contains a potentially unassigned `num2` path. Control-flow proof must come from original IL rather than naive decompiler simplification.
- The `Assembly.Location.Length` condition suggests the section-map path may be particularly relevant for memory-loaded assemblies; this needs IL control-flow validation and runtime testing.
- This pass does not recover the 163 virtual-only methods or prove equivalence for any of them.

## Next evidence needed

1. Original IL for `0x060002EA`, `0x060002EB`, `0x060002EC`, `0x060000D3`, `0x060000D7`, and `0x060000DB` from the *same SHA-256 sample*.
2. Optional method `0x060000DF` and `A3B21017` type output to determine reader invariants.
3. A verified sample byte stream and expected decoder outputs in an isolated VM, only after static logic is validated.

## Reconstruction status

- Module base storage: high confidence static observation.
- Section address mapping: partial, unverified branch details.
- Reader position/state reset: high confidence static observation.
- Byte/uint32 decoding algorithms: partial, not validated.
- Protected application source: unresolved.
