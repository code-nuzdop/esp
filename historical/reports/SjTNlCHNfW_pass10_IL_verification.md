# SjTNlCHNfW.exe — Pass 10 IL verification

## Scope
Seven IL listings from the user-provided `Recovery-Step10.zip`, inspected without executing the EXE. Findings below derive from these specific outputs, not a runtime trace. The seven listings contain 1,076 decoded IL instruction lines in total. These are method-level disassemblies and do not establish that all paths will successfully execute.

## Method evidence

| Token | IL instructions | Conditional/unconditional branch instructions | Directly observed behavior |
|---|---:|---:|---|
| `0x060002EA` | 2 | 0 | Load static `int64 40AB99A9::493E83B7` and return. |
| `0x060000DF` | 5 | 0 | Return `uint32 A3B21017::D38A0391`, declared method return type `int32`. |
| `0x060000D7` | 32 | 2 | Assign input `int32` to `uint32 D38A0391`, then assign that field value to `uint32 78A03A01` after opaque arithmetic. |
| `0x060000D3` | 258 | 5 | Resolve position by `40AB99A9::14B13C9A`, load a byte (`ldind.u1`), perform arithmetic against decoder state, return `uint8`. |
| `0x060000DB` | 232 | 2 | Resolve position by `40AB99A9::14B13C9A`, load a word (`ldind.u4`), perform arithmetic against decoder state, return `int32`. |
| `0x060002EB` | 231 | 19 | Read static mapping array `1F2D38B3`, inspect `FE330A2A` fields and argument, use static `493E83B7` base, return `IntPtr`; contains `BadImageFormatException` path. |
| `0x060002EC` | 316 | 18 | `Marshal.GetHINSTANCE` on a reflected module, save a static base, inspect `Assembly.Location` and image header-like structures, create and fill `FE330A2A[]` mapping array; contains an exception path. |

## Concrete simplification: `0x060000D7`

The first opaque branch tests a local derived from `0x9D3FF721 - 0xEA865E9D` (all arithmetic modulo 2^32). Result is `0xB2B99884`, which is **greater** than `380498978`, so the unsigned `ble.un IL_0000` is false. The next local transformation produces `0xC8AA95F9`, which is not `1929991040` (`0x73095380`), so `beq IL_0020` is false. Therefore, along the initial path the method exits after setting both fields to the supplied bit pattern:

```csharp
// Semantic expression of the observed initial path. Assumes the ordinary unchecked IL arithmetic model.
void SetPosition(int value)
{
    D38A0391 = unchecked((uint)value);
    _78A03A01 = D38A0391;
}
```

`_78A03A01` is a valid C# replacement identifier for the obfuscated field named `78A03A01`.

## Evidence boundaries

- The above does **not** establish a precise general-purpose mapping equation: `0x060002EB` has 19 branches and depends on a runtime-created array.
- The presence of one `ldind.u1` / `ldind.u4` in the readers verifies a direct memory read on that path, **not** which byte is read for every possible runtime state.
- The byte and word readers' rotation/shift-like expressions depend on CLR 32-bit shift-count masking, unsigned operations, arithmetic wraparound, and the evolving decoder state. Their exact semantics need path-aware symbolic execution or instrumented tests.
- The initializer checks the assembly's location, but the observed code does not by itself prove when or whether the mapping array is fully populated in the process.
- An empty decompilation of the entry-point method does not verify that the protected entry point is functionally empty.

## Next evidence needed

1. Confirm the mapping-array elements and the raw bytes at resolved addresses in an isolated runtime, or recover the correct stream from static data.
2. Derive symbolic expressions from all reachable IL paths for `0x060002EB`, `0x060000D3`, and `0x060000DB`.
3. Test a C# reconstruction with identical 32-bit wraparound, signedness, and exception behavior against controlled runtime observations.
4. Document per-method test vectors, address ranges and confidence; do not call the remaining 163 methods restored absent their actual bodies.
