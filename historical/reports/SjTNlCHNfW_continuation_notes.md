# SjTNlCHNfW — follow-up static VM investigation

Analysis performed on 2026-11-17. **No suspicious executable was run.** This note supplements the earlier consolidated report; it is not a completed malware-family identification.

## New findings

- The previously reached nested opcode `0x1A` maps to `D719AC25`, metadata token `0x06000296`. The method pops two VM values (`FB9C7B25.93329331`) and chains calls to `8F0BF53C.DDAEE803`, `8F0BF53C.CB86DE14`, `8F0BF53C.798B5EB6`, and `8F0BF53C.5F11D60F`. This is consistent with **typed value conversion and assignment**, but the exact targeted object and effect require the runtime types/stack values.
- Statically continuing the existing reader state after the handler's bytecode position (`RVA 0x80050B`) yields opcode `0x74`, handler `8C379AB2`, token `0x060002A1`. It calls reader `5B08298E` (`0x060000DB`) and `B6378BA4` (`0x0600028D`), a member-to-type resolver; the next decoded 32-bit value is `0xCC470010`.
- The value `0xCC470010` does **not** look like a standard TypeDef/TypeRef/TypeSpec metadata token. The decoder here may be following a path not reached in actual control flow, or the handler may use a transformed identifier. We have not established which. Do not interpret subsequent bytewise values as real executed opcodes without validating branch/exception state and argument stack.
- This is a **continuation hypothesis**, not a confirmed execution trace. No new malicious functionality or external host was identified from these bytes.

## Reproduction

The prior `static_reader_emulator.py` imports original read-only EXE bytes and parses supplied IL exports without loading the executable. To reproduce the candidate next byte and operand:

```python
from static_reader_emulator import Reader
r = Reader(0x80050B)
opcode, _ = r.execute('0x060000D3')
value, _ = r.execute('0x060000DB')
print(hex(opcode), hex(value))  # 0x74 0xcc470010
```

## Remaining blockers

1. Fully characterize the `0x1A` target VM value types and side effects on the evaluation stack.
2. Confirm the precise effect of exception-region registrations and whether the next bytecode address is executed sequentially.
3. Implement a control-flow-aware static devirtualizer that follows branch targets and nested calls, rather than blindly consuming an instruction stream.
4. Recover actual invoked application APIs and operands before assigning a malicious/benign behavioral classification.

**Safety:** Static read-only analysis only; do not execute the sample on a normal machine.
