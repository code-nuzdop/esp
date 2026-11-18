# SjTNlCHNfW: static VM assignment / reader-state follow-up

Scope: read-only inspection of the supplied EXE, recovered file-backed IL (`SjTNlCHNfW_disassembly.il.txt`), existing `SjTNlCHNfW_second_nested_trace.csv`, and the previously developed offline reader emulator. The executable was not loaded or executed.

## Confirmed: opcode 0x1A is a typed assignment

`0x1A` maps to handler `D719AC25`, MethodDef `0x06000296`.

The handler:
1. Calls `FB9C7B25.93329331()` twice (MethodDef `0x06000071`), preserving first-popped VM value as the destination and second-popped value as the source.
2. Obtains the destination type through `destination.DDAEE803()` (virtual MethodDef `0x06000162` on the base class, dispatched to the concrete destination value's override).
3. Calls `source.CB86DE14(destinationType)` (MethodDef `0x0600015C`) to convert to the destination's type.
4. Unboxes/extracts the result through `798B5EB6()` (virtual MethodDef `0x06000148`).
5. Calls `destination.5F11D60F(convertedObject)` (virtual MethodDef `0x0600015B`) to perform the actual write.

Representative behavior, not original source:
```
VMValue destination = stack.Pop();
VMValue source = stack.Pop();
object converted = source.ConvertTo(destination.GetRuntimeType()).Unwrap();
destination.SetValue(converted);
```

This verifies **assignment semantics**, but not the concrete target at this invocation. Whether FieldDef `0x04000191` (the VM reader field) is actually overwritten depends on the object produced by `0x39`, the operand's wrapper kind, and stack-flow/conversion behavior. The earlier report's wording 'assignment to the reader field' was therefore stronger than proven.

## Conditional continuation if the reader is unchanged

Replayed the previously verified 23 reader operations at nested selector `0x7FE224` using the saved `static_reader_emulator.py`, preserving both decoder-state fields. Immediately after opcode `0x1A`:

- cursor RVA: `0x7FE1EE`
- `D38A0391 = 0x007FE1EE`
- `78A03A01 = 0x007FE252` (numeric fields in the emulator, not observed runtime state)
- next decoded opcode **assuming the reader is unchanged**: `0x9C`, handler `74B39F1C` (MethodDef `0x060002CE`). Its method body starts with a byte-reader `uint32` call, then `EF8B98AF` (`0x060002B4`) to resolve a `MethodBase`.
- decoded 32-bit operand under the same unchanged-reader assumption: `0xF735885A`.

`0xF735885A` is not a normal `MethodDef` / `MemberRef` / `MethodSpec` metadata token, and the source code of `0x9C` immediately passes its decoded integer to the method resolver. Thus the naive unchanged-reader continuation fails a useful consistency check. **This strengthens the need to model the preceding assignment, or to validate whether that control-flow path is reachable.** It does not establish what the replacement reader is, and it does not justify guessing the next instructions.

## Next work with highest expected value

1. Determine the exact concrete wrapper produced by opcode `0x39` and its `DDAEE803` / `5F11D60F` implementations. This is necessary to establish what `0x1A` writes.
2. Trace the symbolic stack and any aliasing across the immediately preceding array/field/conversion instructions; do not assume top-of-stack objects correspond to names of metadata tokens.
3. If a new `A3B21017` reader object is assigned, recover its constructor arguments/cursor and resume using its own cipher state.
4. Keep static-observation claims separate from reachability and runtime-behavior claims. No malicious capability can be established solely from this excerpt.
