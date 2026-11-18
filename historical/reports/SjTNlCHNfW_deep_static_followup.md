# SjTNlCHNfW.exe — extended, read-only VM reconstruction

## Scope and conclusion

The original user-supplied executable and existing recovered IL/metadata were inspected **as data only**. The executable was not loaded, launched, or contacted over the network. A previously recovered *offline* reader emulator was used only to evaluate the sample's encoded bytes and a narrow supported subset of reader IL.

**Most important new result:** The nested VM's apparent `B32A609B` "reader assignment" is a **reader cursor/state reset via an inherited setter**, not replacement of the `A3B21017` reader object. The target cursor depends on **element 5 of a protected static `System.UInt32[]` field**. The field's own type initializer is virtualized; its initial bytecode declares a **52-element `System.UInt32` array** and also reaches a reader-cursor reset. This explains why decoding subsequent bytes as though the original cursor continued led to an invalid .NET metadata token.

The new findings **do not** identify the application's ultimate behavior, any malicious API call, exfiltration, persistence, or a validated remote endpoint. Virtualized initialization and branching are not proof of malware.

## Sample identity

- Filename: `SjTNlCHNfW(1).exe`
- SHA-256: `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`
- Byte size: 6,783,488
- PE32 managed image, CLR `ILONLY` flag. Previous memory snapshot used the 64-bit .NET Framework CLR. The original image has virtual-only sections with no file-backed method bodies. See the prior `SjTNlCHNfW_final_static_investigation.md` for PE-level details.

## New binary metadata findings, independently checked

| Evidence | Direct finding |
|---|---|
| TypeDef `0x02000018` | `EAA46804`, base of `A3B21017` |
| TypeDef `0x0200002D` | `A3B21017` directly **extends `EAA46804`** |
| MethodDef `0x060000D7` | `A3B21017.CD90E311(int32)` writes fields `0x04000093` (cursor) and `0x04000094` (rolling cipher state) |
| TypeDef `0x02000026` | `E4113232` field/value reference wrapper |
| MethodDef `0x060000B0` | `E4113232.5F11D60F(object)` calls `FieldInfo.GetValue` on a stored instance, casts the resulting value to `EAA46804`, then calls its virtual `CD90E311(int32)` |
| MethodDef `0x060000B2` | `E4113232.DDAEE803()` returns `typeof(System.Int32)` |
| FieldDef `0x04000191` | `6633B699.B32A609B` is a reference to the VM reader `A3B21017` |
| FieldDef `0x04000182` | `76B7C6BB.D0244F83`: **static field**, signature `FIELD SZARRAY U4`, i.e. `System.UInt32[]` |
| MethodDef `0x06000239` | `76B7C6BB` type initializer delegates to VM dispatcher selector **`0x007FC7AF`** |
| MethodDef `0x060002B5` | `79AF42A2` invokes MemberRef `0x0A000141`, **`System.Array.CreateInstance`** |
| MethodDef `0x0600027B` | `7026BDB3` constructs the `E4113232` reference wrapper after resolving a field |
| MethodDef `0x06000296` | `D719AC25` pops two VM values, converts source to destination declared type, and calls destination virtual setter |

Crucial distinction: `E4113232.5F11D60F` does **not** perform `FieldInfo.SetValue` to overwrite `6633B699.B32A609B`. Instead it fetches the **reader object currently held in that field** and calls the inherited `CD90E311` setter, which updates **both** cursor and cipher state. (The separate `8E292119` wrapper, created by opcode `0x12`, *does* use `FieldInfo.SetValue`.)

This direct call relationship is sufficient to resolve the earlier ambiguity about the purpose of opcode `0x39`, conditioned on its field-target and stack values being valid and the setter path executing successfully.

## Second nested VM: decoded path to reader reset

Reader selector: **RVA `0x007FE224`**. The separately generated CSV contains the 23 decoded reader operations, stopping at the state-changing instruction.

1. Header: `ushort 0`, `System.UInt32` (`0x01000058`), `System.Enum` (`0x01000066`).
2. After stack setup, opcode `0x12` resolves **`0x04000182`**, the static `System.UInt32[]` field.
3. Opcode `0x95` with type token `System.UInt32` reads the element indexed by **5**.
4. Opcode `0x24` performs a typed conversion to `System.UInt32`.
5. Opcode `0x39` resolves **`0x04000191`**, the VM's reader field, wrapping the current reader in a reference object.
6. Opcode `0x1A` performs typed assignment; because the destination wrapper is `E4113232`, its setter targets `EAA46804.CD90E311(int32)`, resetting the reader's cursor and rolling state.

Consequently the following byte at the *old* RVA `0x7FE1EE` must not be trusted as the next executed opcode if this assignment succeeds. The previously reported opcode `0x9C`, operand `0xF735885A`, and invalid metadata interpretation were a **conditional stale-reader decode**, not a verified execution sequence.

The exact new cursor value cannot yet be determined from this instruction stream alone; it depends on the runtime contents of `76B7C6BB.D0244F83[5]`. The supplied early-process memory dump has not yielded a verified initialized copy of that array.

## New: array field initializer's protected stream

The field belongs to type `76B7C6BB`, whose `.cctor` uses VM dispatcher with **selector `0x007FC7AF`**. Reading directly from the original EXE bytes with preserved reader state produces the following **20 consecutive verified read records**:

| Operation | Relevant decoded value | Interpretation |
|---|---|---|
| `0x10`, operand | `0` | Push zero |
| `0x50`, `0x50` | — | Stack setup/discards |
| `0x10`, operand | `52` (`0x34`) | Array length |
| `0x1B`, operand | `0x01000058` | Create `System.UInt32` array, via `Array.CreateInstance` |
| `0x01`, operand | `0` | Resolve a VM value; concrete object not independently established |
| `0x12`, operand | `0x04000182` | Reference the `D0244F83` static array field |
| `0x1A` | — | Typed assignment, consistent with storing created array |
| `0xC3`, operand | `0` | Resolve a VM value |
| `0x10`, operand | `0` | Push zero |
| `0x39`, operand | `0x04000191` | Wrap current VM reader's cursor setter |
| `0x1A` | — | Typed assignment: candidate reader-cursor reset |

The **read cursor at the end of this static sequence is `0x007FC783`**. It is **not** correct to assume the next opcode is the byte originally stored there: the last handler may reset the reader's cursor and rolling state.

The 52-element declaration is **not** proof that element 5 already has a concrete value at that moment; the field may be populated in subsequent virtualized code. The second nested stream may execute at a different point after initialization.

## Why full static devirtualization is still incomplete

To continue accurately, a control-flow- and object-aware interpreter would need to reconstruct the VM's stack values, static-field writes, wrapper virtual calls, and cursor-reset values across **both** protected flows. The target `D0244F83[5]` is not embedded as an ordinary visible `ldc.i4` in the confirmed excerpt. Guessing the target from surrounding encrypted bytes produces false traces. The early-process memory dump includes the original mapped image but did not recover missing virtual-only method bodies; a pattern scan also did not produce a **verified** instance of this particular initialized 52-element array.

The available evidence confirms substantial virtualized setup, array manipulation, reflection-capable invocation, and an activation/deactivation string family; it does **not** substantiate claims that this sample steals credentials, persists, contacts a particular host, or is harmless. Such claims require actual resolved application-level calls and parameters, not mere API references or protection-related code.

## Reproduction and limitations

- `verify_reader_jump.py` verifies the original EXE hash and all 43 decoded records across both streams, then writes `SjTNlCHNfW_new_reader_jump_evidence.csv`.
- `static_reader_emulator.py`, `vm_opcode_map.csv`, recovered IL disassembly, and the original sample are used as **read-only analysis inputs**. The emulator is intentionally narrow, not a complete emulator of the protected executable.
- New metadata facts above were checked directly against original `#~`, `#Strings`, and `#Blob` streams, the recovered file-backed method IL, and the caller/callee tokens.
- The script does **not** execute the original PE or call its .NET code.

**Bottom line:** The formerly ambiguous “reader assignment” is a specific `EAA46804.CD90E311` cursor/state update, and its input is traceable to a protected static `uint[]` lookup. This is a real improvement in understanding the VM but not a full recovery of the underlying program's operational behavior.
