# Voice trial note limit: Synthesizer V Studio 2 Pro 2.3.0

## Result and actual changes

Created `patch_voice_limit.py`, a standalone Windows x64 Python runtime patcher. Its default `LIMIT = -1` selects the application's existing unlimited-note sentinel. Set `LIMIT = 9999` for a finite cap, or `LIMIT = 40` to restore the original immediate in an already patched process.

Created this knowledge document. No existing launcher, DLL, analysis capture, activation data, project, or installed executable was modified. The patcher was not executed, and no compilation checks or functional tests were run. Inspection of the already running application used read-only process access; the application was not launched, suspended, injected into, patched, or closed during this work.

This is not a permanent on-disk EXE patch. Runtime writes occur only when the user runs the script and confirms `APPLY`. Functional behavior remains unvalidated.

## Exact target

- Path: `C:\Program Files\Synthesizer V Studio 2 Pro\synthv-studio.exe`
- File/product version: `2.3.0`
- Architecture: AMD64
- File size: 17,445,928 bytes
- SHA-256: `37592b7d3c41ffaf0491b6b335ee630a34f03416b85fe9081021e6981eb5c2d3`
- Preferred image base: `0x140000000`; actual base varies with ASLR.
- Runtime `.text`: RVA `0x1000`, virtual size `0x1193338`.

The EXE is packed: `.text`, `.rdata`, and several other sections have zero raw-data size and pointer. Their runtime RVAs do not identify ordinary code bytes in the disk file. A generic RVA-to-offset conversion can return unrelated packed bytes rather than fail. Do not use a global binary replacement of 40, or write to the file at the runtime RVA.

## Usage

1. Save work. Open the original `synthv-studio.exe` and wait for the editor window. Keep only one instance of this installation running.
2. Stop playback/rendering; avoid interacting with the app while applying the patch.
3. Optionally change the top-level `LIMIT` in `patch_voice_limit.py` from `-1` to `9999`.
4. From this directory, run `python -B patch_voice_limit.py` using 64-bit Python on Windows. The script uses only the standard library.
5. Check the displayed target/PID and type `APPLY`.
6. Reselect the voice or reopen the saved project if cached limits persist. This refresh procedure is a suggestion, not validated behavior.

Run the patcher again after every application restart. Closing the app discards the runtime edit; the original EXE needs no restoration. Alternatively, set `LIMIT = 40` and apply again to restore the instruction for the current session, then refresh cached state.

The script does not elevate privileges. If Windows denies process access, run the application and script at compatible privilege levels. Any unexpected runtime or hash mismatch requires fresh analysis, not removal of the guards.

## Current-build findings

### Cap getter

Function RVA `0x8C1EC0`, length `0xA2`, computes the local note cap from voice/editor states:

- Voice record comes from the call at `0x8C1EDC` to `0x908270`.
- Voice type is read at record offset `0x30`.
- Voice type 2 consults editor state via `0x9083C0`; matching non-trial state selects the unlimited branch.
- Voice type 1 selects an internal state of 1 or 2 according to the byte at record offset `0x40`. Both converge on the 40-note branch. The exact meaning of this byte was not independently established here.
- Other states retain their existing behavior.

Key instructions:

| RVA | Original instruction | Role |
| --- | --- | --- |
| `0x8C1F25` | `mov eax, 1000` | Separate editor-limited path; unchanged |
| `0x8C1F35` | `mov eax, 40` | Voice trial note-cap path |
| `0x8C1F45` | `mov eax, -1` | Existing unlimited path; unchanged |
| `0x8C1F55` | Epilogue returning zero | Other state; unchanged |

The only write is the four-byte signed immediate at RVA `0x8C1F36`, offset `0x76` from the getter start:

- Original: `28 00 00 00`
- Unlimited: `FF FF FF FF`
- 9999: `0F 27 00 00`

The `B8` opcode, instruction lengths, branches, calls, and function prologue/epilogues are unchanged. Unlike replacing the whole getter with a constant-return stub, this preserves the other state-dependent paths.

### Enforcement consumer

Direct call at `0x94FEA8` reaches this getter. The result is copied into EBX, and `test eax,eax; setg al` sets a positive-cap flag at `0x94FEAF` through `0x94FEB4`.

At `0x94FF9D`, the cap is sign-extended and saved at `[rsp+0x38]`. The note loop then uses:

- `0x9501FC`: load the saved cap.
- `0x950201`: `test rax,rax`.
- `0x950204`: `jle 0x95020F`, skipping the cap-derived mute condition for nonpositive values.
- `0x950206`: compare the note index in R13 against the cap.
- `0x95020B`: select a mute flag when a positive cap has been reached.
- `0x950211`: combine that flag with other mute conditions.
- `0x9502DE`: store the resulting flag at note-object offset `0x9C`.

This establishes that `-1` disables this local note-count mute condition. It does not establish successful synthesis, export, entitlement validity, or every other consumer's behavior. Another direct caller at `0x8B35C3` stores the cap along with separately computed voice/editor state.

### Warning text is independent

The voice warning string is at RVA `0x14E0FF0`, referenced from `0xB70414`. Its formatting code independently loads `r8d = 40` at `0xB70478`; it does not obtain that number from this getter. Therefore the dialog can still say 40 after the actual cap instruction is changed. The script intentionally leaves this separate UI code untouched rather than present cosmetic text changes as enforcement changes.

The editor warning has its own 1000-note formatting immediate at `0xB702B7`. Export and rendering warnings also have separate paths. None is patched here.

## Safeguards and limits

The script checks the disk fingerprint, exact process path, and full runtime getter bytes before writing. Only the four-byte immediate may differ, and its previous value must be 40, 9999, or -1. It finds the live module base rather than hard-coding the observed ASLR address. It refuses zero/multiple matching instances and uses a named mutex to prevent concurrent copies of this patcher.

After confirmation, it requests whole-process suspension with `NtSuspendProcess`, rechecks the bytes, temporarily changes page protection, writes only the immediate, reads it back, flushes the instruction cache, restores protection, and resumes in a `finally` block. Write failure triggers an attempt to restore the previous immediate. Native API failures are reported; a resume failure may leave the app suspended and require Task Manager intervention. Force-killing the patcher during the brief suspended interval can also leave the app suspended. Save work first.

No runtime safety or audio tests have been performed. Anti-tamper behavior, caching, later code replacement, or other licensing checks can still interfere. The patch changes neither trial expiry nor the need for an active internet connection, activation, voice data, export permissions, or engine authorization. Unlimited means only the identified local note-count cap is disabled.

## Research history and replication

Existing `runtime_patch.h` and `runtime-evidence.json` describe an older 2.2.1 build with SHA-256 `7d81044df4827d21a1f232d2eb42d37d5ac87648abfb406a34f027e4e74ca35b`. Its captured getter at `0xAB0AF0` has `mov ebx,40` at `0xAB0B51`. Those addresses and bytes are stale for the current installed EXE. The older offline-rendering attempt was already reported as unsuccessful in `offline-investigation.json`; this new cap-only patch does not solve that failure.

Read-only inspection used `pefile` for disk layout and `capstone` for disassembly, with standard-library ctypes calls to `OpenProcess`, `K32EnumProcessModulesEx`, and `ReadProcessMemory` for the already running image. Those third-party packages are research tools, not patcher dependencies.

To reproduce the analysis on the supported build:

1. Check version, file size, and SHA-256; inspect raw section sizes before interpreting RVAs as disk offsets.
2. Obtain the live main-module base and read its `.text` section read-only.
3. Disassemble RVA `0x8C1EC0` for `0xA2` bytes; compare against `ORIGINAL` in the patcher.
4. Find direct relative calls to that getter and follow the sign-extended result into the positive-cap comparison described above.
5. For UI investigation, follow the RIP-relative reference to the voice warning and inspect its independent formatting immediate.

An initial search limited to `mov ebx,40` did not find the current getter; this version returns the immediate in EAX. Broadening to register-immediate loads of 40 near the separate 1000 constant identified it. A string-reference disassembly attempt also overproduced output when an INT3 boundary search failed; future analysis should always bound the fallback range instead of starting at offset zero. No analysis log is retained.

## Outstanding work

User observation is still needed for note playback beyond 40, cache refresh, behavior with licensed/expired voices, warning presentation, and restoration. Do not report these as working based only on the instruction analysis or memory-readback mechanism.
