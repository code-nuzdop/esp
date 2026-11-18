# SjTNlCHNfW.exe — pass 4 initializer and dispatch analysis

## Scope / source
Original SHA256 `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`. Static analysis only; no code executed or patched. Examined IL method 739 (`0x060002E3`) and method 705 (`0x060002C1`) from previously recovered instruction streams.

## Constructor 739
- **6,745 decoded IL instructions**.
- **256 `ldftn` sites**, each pointing to an internal MethodDef, but only **93 distinct method targets**.
- For each `ldftn` there is an associated `newobj 0x06000082` followed by `callvirt 0x0A00010C`; these repeated IL triplets are consistent with making and registering delegates or callbacks. This is a *pattern-level inference*: external MemberRef signature and container type have not been verified.
- All 256 target occurrences refer to **256 decoded** and **0 not-decoded** internal methods. The target occurrences are not synonymous with 256 unique handlers.
- Top targets by registration count: 0x060002D8: 12, 0x060002E2: 11, 0x060002A3: 9, 0x060002D2: 8, 0x060002BC: 8, 0x06000287: 7, 0x060002CE: 7, 0x06000290: 6, 0x060002BD: 6, 0x060002BF: 6.
- These sites are syntactic references and not proof all registrations occur at runtime: opaque predicates and branches might gate or repeat statements.

## Initializer 705
- **205 IL instructions** and **16 call/newobj occurrences** (9 internal, 7 MemberRef).
- IL contains exception-flow instructions (`leave`, `endfinally`) and branch-heavy control flow, so a linear IL listing does not represent actual execution order.
- Calls and available token names listed in `SjTNlCHNfW_initializer_705_calls.csv`; a resolved external metadata signature and exception-clause table are still needed before confident behavioral descriptions.

## Exact outputs
- `SjTNlCHNfW_registration_sites.csv` — one row for each of 256 `ldftn` callback reference sites.
- `SjTNlCHNfW_registration_targets.csv` — 93 unique target methods and how often each appears.
- `SjTNlCHNfW_initializer_705_calls.csv` — all call/new-object sites in initializer 705.

## Limits and patch safety
No missing virtual-only entry-point methods recovered. The presence of a repeated callback registration pattern alone does not establish a licensing, anti-tamper, or activation implementation. No patch locations confirmed; no EXE modified.
