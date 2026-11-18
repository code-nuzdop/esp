# SjTNlCHNfW — VM continuation correction and deeper static reconstruction

**Method:** offline arithmetic simulation of the original EXE bytes and previously exported managed IL. The sample was **not executed**. These are statically reconstructed instruction/operand streams, not an observed live execution trace.

## Critical correction: preserve the rolling reader state

The earlier continuation note (`SjTNlCHNfW_continuation_notes.md`) incorrectly constructed a *fresh* reader at RVA `0x80050B` after completing 23 reads on the nested reader. The reader has **two mutable 32-bit fields**, `D38A0391` (cursor) and `78A03A01` (decoder state). Resetting both fields to the current cursor creates a different cipher state.

- Incorrect reset-derived result: `0x74`, operand `0xCC470010` (not usable as evidence of a genuine instruction).
- Correct continuation using the **same reader instance**: opcode `0x01` at RVA `0x80050B`, operand `0`.
- Prior-to-continuation reader fields: `D38A0391=0x80050B`, `78A03A01=0x04802B4D` (value independently recoverable with the static reader script).

The invalid-looking token and interpretation of opcode `0x74` as the next executed instruction should therefore be **withdrawn**. It was a decoder-state mistake, not a discovered behavior of the executable.

## Consecutive typed local-slot registrations

From `0x80050B`, the statically decoded nested VM contains **124 consecutive four-instruction groups** registering local indices `0` through `123`, inclusive. The template is:

1. Opcode `0x01` or alias `0xC3` (`B1190689`) with encoded operand `0`.
2. Opcode `0x10` (`B40B1435`) with encoded operand `0`.
3. Opcode `0x10` (`B40B1435`) with an encoded .NET type token.
4. One of `0xA8`, `0xC4`, `0xE3`, `0x54`, `0x70`, `0x77` (all map to `76862C12`) with a 16-bit sequential local index.

`76862C12` reads a `short`, pops the type token and other VM stack values, uses `B6378BA4` to resolve a `Type`, performs conversion/default-value logic, and assigns a slot with `FB9C7B25.21A7D23C`. The exact objects assigned are not guaranteed to be primitive zero, because the `0x01` handler resolves the encoded value via additional VM logic.

The per-slot type tokens and 124 indices are in `SjTNlCHNfW_verified_124_local_slots.csv`; `SjTNlCHNfW_typed_124_local_slots.csv` additionally resolves all TypeRef names. Examples:

- `0x01000058` = `System.UInt32` (54 slots)
- `0x01000057` = `System.Int32` (13 slots)
- 22 slots use `TypeSpec` tokens and seven use `TypeDef` tokens; their complete type signatures/names were not resolved in this pass.
- The resolved TypeRefs also include `System.Reflection.Emit.DynamicMethod`, `System.Reflection.Emit.DynamicILInfo`, `System.Reflection.MethodBase`, `System.Reflection.MethodInfo`, `System.Reflection.FieldInfo`, `System.Reflection.Module`, and basic primitive types. These are **VM local types**, not proof those API types are used by a malicious payload.

**First departure from the template:** opcode `0x50` (stack pop) at RVA `0x7FFC53`, then opcode `0x10` pushes selector **`0x7FE224`**, and opcode `0x53` calls another nested VM. These bytecode values were obtained from the preserved reader state; the call target is in the file-backed region of the original executable.

## A second nested VM at RVA `0x7FE224`

The next nested reader starts with header values:

- `ushort 0`
- `uint32 0x01000058` = TypeRef `System.UInt32`
- `uint32 0x01000066` = TypeRef `System.Enum`

Subsequent decoded instruction-level operations include:

- `0x10` push zero; two `0x50` stack pops;
- `0xC3` (same implementation as `0x01`) with operand `0`;
- `0x12` (`35A1509D`) with `FieldDef 0x04000182`, constructing a VM field-reference wrapper;
- `0x0D` (`DF3D6327`) typed conversion;
- `0x10` with integer `5`;
- `0x95` (`C5931FB9`) with `TypeRef 0x01000058` (`System.UInt32`), an array-element read helper (`Array.GetValue` in the handler);
- `0x24` (`C9BF0D8B`) with `System.UInt32`, converting a stack value;
- `0x10` with zero, then `0x39` (`7026BDB3`) with `FieldDef 0x04000191`, the VM's **bytecode reader** field `B32A609B`;
- `0x1A` (`D719AC25`) assignment/conversion via VM value interfaces.

**Stop point:** the last sequence can assign to the interpreter's **reader object**. The next apparent opcode decoded using the *old* reader state is not trustworthy without determining whether the `0x1A` handler replaced or mutated the reader and how its stack operands resolve. Do not interpret any invalid-looking method token decoded after this point as proof of an actual application call.

## What this changes—and what it does not

This establishes a long, regular block of **typed VM-local initialization** and a further nested VM selector beyond the first exception-region records. It is materially more of the protected execution structure than previously decoded. The recognizable type tokens and sequential indices are independent consistency checks on reader synchronization.

It **does not yet identify** a malicious API, a contacted host, a persistence mechanism, or a final benign/malicious classification. `0x95` is a *capability* for reading array elements, not evidence that any particular sensitive array was accessed. The exact execution path and actual stack values remain symbolic. The reader write is a concrete reason that purely linear bytecode decoding stops being reliable.

## Reproducibility

`recover_vm_nested_locals.py` performs the static reader calls and asserts the expected typed registrations and second nested segment. It reads original EXE bytes and saved IL text via `static_reader_emulator.py` without importing or executing the EXE. The output CSVs are `SjTNlCHNfW_verified_124_local_slots.csv` and `SjTNlCHNfW_second_nested_trace.csv`. `enrich_vm_type_tokens.py` resolves the TypeRef names for `SjTNlCHNfW_typed_124_local_slots.csv`.

**Next investigation target:** statically recover stack/value wrapper semantics around `D719AC25` and `FieldDef 0x04000191` so the second reader mutation can be modeled, then resume decoding from the correct reader instance. Runtime behavior, network destinations, and application purpose remain unproven.
