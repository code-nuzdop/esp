# SjTNlCHNfW.exe — pass 5 semantic recovery and delegate registration resolution

## Scope
Static inspection only of the original executable, SHA-256 `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`. Source data are the original binary's CLI metadata, recovered IL and pass-4 registration-site inventory. No code was run or modified.

## Conclusive metadata resolution
- **Delegate type**: obfuscated `95969DA2` (TypeDef row 27; extends `System.MulticastDelegate`).
- **Delegate constructor**: MethodDef `0x06000082`: `instance void .ctor(object, native int)`.
- **Delegate invoke**: MethodDef `0x06000081`: `instance void Invoke()`; takes **no parameters** and returns **void**.
- **Registration receiver**: `System.Collections.Generic.Dictionary<uint32, 95969DA2>`, TypeSpec row 16.
- **Registration operation**: MemberRef `0x0A00010C`: its `set_Item` method, with the generic signature instantiated as `void set_Item(uint32 key, 95969DA2 callback)`. It assigns/replaces dictionary entries, not event subscription.
- **Dispatcher lookup**: MemberRef `0x0A000152` (`get_Item`) used by method `0x060002C1`, followed immediately by MethodDef `0x06000081` (`Invoke`): this statically establishes keyed lookup + callback invocation.
- **Instance field**: `0x04000197` holds that dictionary. Other instances fields hold supporting state (`0x04000191` class `A3B21017`, `0x04000195` class `FB9C7B25`).
- **Constructor**: `0x060002E3` has 256 `ldftn`/delegate-construction/`set_Item` patterns, but only 93 unique method targets. All 93 methods are instance `void()` on obfuscated class `6633B699`.

## Dispatcher interpretation
This is a uint32-keyed dispatch table of parameterless handlers. Registration keys are computed in an obfuscated instruction stream, so neither exact keys nor which branches execute is established here. Multiple registration sites can target the same function. The dictionary indexer would replace an existing entry on duplicate key; it is not possible to assert whether collisions occur without evaluating the key expressions on the reachable execution paths.

The dispatcher method `0x060002C1` has signature `object (object[] args, int32 selector)` and calls `Dictionary<uint32,95969DA2>.get_Item`, then `95969DA2.Invoke`. It also accesses runtime state, calls helpers, iterates a `List<native int>` and frees unmanaged allocations via `Marshal.FreeHGlobal`. Its complete observable behavior and return value are not proven without full branch and exception-flow validation.

## Semantic recovery of the 93 targets
- **93/93** callback method signatures resolved: `instance void()`.
- **22** callbacks contain external MemberRef calls; **71** call only internal MethodDefs (or perform local operations) in their recovered bodies.
- **6** include direct reflection or Reflection.Emit API calls, **6** include direct runtime-type inspection, **13** contain explicit `throw` instructions, and **2** write fields.
- The common internal helper `FB9C7B25::93329331` occurs in **78** distinct callback methods; helper `FB9C7B25::E61629A6` occurs in **80**. Signatures are respectively `instance 8F0BF53C ()` and `instance void (8F0BF53C)`. They appear to retrieve and commit an intermediate object, but their exact semantics need further trace validation.
- Direct external references include `System.Reflection.Emit.DynamicMethod`, `ILGenerator.Emit`, `MethodBase.Invoke`, `Type.IsAssignableFrom`, `Marshal.AllocHGlobal`, `ArgumentException`, and array construction/access. Those are **API facts**, not proof a particular callback is reached at runtime.

## Specific higher-information callbacks
- `0x06000287`: synchronization (`Monitor.Enter/Exit`), dictionary lookup/cache of `DynamicMethod`, reflection and emission API calls. Consistent with cached dynamic method generation.
- `0x060002CE`: inspects method parameters; builds `Dictionary<int32, 8F0BF53C>`; interacts with reflected types and emission-related helpers. Consistent with method-argument transformation/generation.
- `0x060002BD`: includes `Type.IsValueType`, `Activator.CreateInstance`; consistent with value-type handling.
- `0x060002AF`: includes `Nullable.GetUnderlyingType` and `FormatterServices.GetUninitializedObject`; consistent with object/value initialization handling.
- `0x060002D5`: calls `Marshal.AllocHGlobal`, adds an `IntPtr` to a list; consistent with unmanaged buffer allocation and bookkeeping.
- `0x06000283`: checks runtime type assignability and can construct/throw `InvalidCastException`; consistent with type validation.

## Source files
- `SjTNlCHNfW_93_callback_semantic_inventory.csv`: 93 rows with exact method token, signature, IL instruction count, branch count, direct internal/external calls, field touches, source literals, and conservative functional classification.
- `SjTNlCHNfW_callback_helper_edges.csv`: direct callback-to-helper references.

## Limits
There is not enough evidence to assign a unique, reliable one-line business purpose to every callback; most functions interact with the same internal obfuscated helper classes. IL decoding is not equivalent to devirtualization, path reachability proof, or runtime verification. This pass does **not** recover the virtual-only entry point or produce validated patch offsets. No executable bytes changed.
