# SjTNlCHNfW.exe — pass 3: conservative IL normalization and function triage

## Basis
- Original input SHA-256: `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`.
- Based on recovered, file-backed IL streams and call graph. Static only, executable not run or modified.
- 650 previously decoded method bodies were reprocessed.

## Normalization
- Removed **106** obvious dead assignments (`ldc.*` or `ldnull` followed by `stloc`) in **105** methods, only when that local variable is never read/taken by address and neither instruction is a branch target.
- Preserved original instruction offsets in cleaned view. This is a **display-only** simplification, not an ECMA-335 rewriter or a patch.
- Did **not** eliminate complex opaque predicates, reassemble IL, parse all EH clauses, or recover virtual-only methods.

## Automatically classified short patterns
- Found **71** short functions matching narrow accessor, wrapper, or token-helper patterns after cleanup. Counts: {'field getter + unsigned 16-bit conversion': 6, 'field getter': 35, 'type token -> external helper -> return': 14, 'field getter + signed byte conversion': 5, 'field -> external helper -> return': 3, 'field null initializer': 1, 'single-argument call wrapper': 3, 'field setter': 1, 'field getter + unsigned byte conversion': 3}.
- These are syntactic descriptions: an obfuscated name, helper call, or field may still hide domain behavior.
- Candidate file lists exact original tokens and operand values.

## Example: MethodDef 0x06000359 (857)
- Original IL performs `arg0 = arg0 - 2`, then checks unsigned `arg0 >= 4`. It returns **3** if true, otherwise returns the adjusted `arg0`.
- Pseudocode: `uint32_t x = (uint32_t)(arg0 - 2); return x >= 4 ? 3 : x;` subject to the method's actual argument and return signatures, which have not been fully verified.
- This demonstrates real branch-level interpretation for a method, rather than interpreting obfuscated function names.

## Example: MethodDef 0x06000018 (24)
- `ldarg.0; ldfld 0x0400000D; conv.i1; ret`.
- Reads field #13 from the first argument and converts to signed 8-bit before returning; full type metadata is still needed for exact source-level signature.

## Example: MethodDef 0x06000014 (20)
- `ldtoken 0x010000BA; call 0x0A000039; ret`.
- Retrieves a type handle and passes it to an external helper; likely a type-reflection wrapper, but external MemberRef signature is unresolved.

## Limits
- The missing entry point (MethodDef #35) is still in a virtual-only section. Recovery of its IL is not possible from the listed raw method RVA alone.
- No license-validation or networking patch sites were validated; no modified EXE produced.
- Reported earlier CFG totals remain structural, not runtime-reachability proofs.

## Produced
- `SjTNlCHNfW_cleaned_il_view.txt`: offset-preserving cleaned IL display for 650 decoded methods.
- `SjTNlCHNfW_candidate_method_behaviors.csv`: narrowly classifiable functions and exact IL.
