# Static analysis report: SjTNlCHNfW.exe

## Identification
- SHA256: `119883c62a2e832f0e9058e0d88e391f15820674cdd33d79845c73c58d63ea40`
- Size: 6,783,488 bytes
- PE32 x86 Windows GUI executable with CLR/.NET metadata; entry-point MethodDef token `0x06000023` (method 35).
- .NET metadata declares **888 MethodDef rows**, **138 TypeDef rows**, **550 FieldDef rows**.
- Heavily obfuscated names and non-standard PE sections; two virtual-only sections (no corresponding raw bytes) complicate disassembly.

## Method-body analysis (header-level, not full decompilation)
- fat: 650
- no-body: 75
- invalid-fat: 23
- invalid-header: 107
- tiny: 33

- `fat`/`tiny` counts indicate that a recognizable header could be parsed; these are **not** proof the following bytes decode as valid, meaningful IL. For example, method 38 has a tiny header followed by random-looking bytes.
- `invalid-header` / `invalid-fat` mean the declared method location does not contain plausible ordinary IL headers. This includes the CLR entry-point method 35, which is a major obstacle to tracing startup behavior.
- `no-body` entries cover delegates, interfaces, abstract/runtime/PInvoke methods; they are not automatically evidence of encryption.

## Supported functionality indicators (not full control-flow attribution)
- Visual Basic / WinForms startup with `OnCreateMainForm`, generated settings, background worker and application shutdown hooks.
- UI references including `asmjit.Form1`, `Application.Run`, `Hide`, `Show`, and form properties.
- System APIs and members related to MD5/SHA-1 hashing, HTTP `WebClient`, DNS, network interfaces, physical/MAC addresses, Base64, and environment paths.
- Strings associated with activation/deactivation workflow: `activation.php?code=`, `type=activation&code=`, `&hwid=`, `&hash=`, `deactivation.php?hash=`, `type=deactivation&hash=`, plus a license-warning message.
- Reflection.Emit and dynamic methods; consistent with a custom runtime/loader/obfuscation or runtime method reconstruction but no proven precise mechanism.
- P/Invoke module references: `shell32.dll`, `kernel32`.

## Patching guidance
1. Work on a copy, not the original; baseline SHA-256.
2. Determine whether the program uses a protective loader or runtime IL restoration. The protected entry point and apparent invalid IL make direct hex edits especially risky.
3. For normal .NET IL: locate MethodDef by token, disassemble decoded IL, change only verified control-flow/constant/instruction sites, maintain stack balance and branch targets, and rebuild metadata and exception-handler tables as needed. Strong-name / Authenticode signatures or anti-tamper can invalidate the edit.
4. For native code: only modify validated native instructions with architecture-aware branch offsets; do not treat the entire PE as x86 because its logic is managed .NET.
5. Do not patch a method merely because of a suspicious name. The CSV distinguishes what is verified from what remains undetermined.

## Inventory
`SjTNlCHNfW_function_inventory.csv` contains all 888 MethodDef tokens, type names, RVAs, body-header observations, raw-byte previews where mapped, and a per-row patchability assessment. The `assessment` field is deliberately explicit about unknown functions; no unverified behavioral claims have been invented.

## Limitation
This is static metadata and limited method-header analysis, not a full unpacked IL decompilation or runtime trace. Definitive semantics for all 888 methods require obtaining the decoded method bodies and tracing cross-references/call sites, ideally under a controlled isolated VM.
