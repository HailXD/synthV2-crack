# RFC 1: Reversible Synthesizer V trial changes

## Status

The requested target is now permanent-license behavior for both application and voicebanks, not a 1,000-note replacement cap. Analysis has confirmed the trial/permanent enum mapping, separate expiry fields, the note-cap decision, and parts of the export/rendering paths. A persistent patch strategy for the packed executable and complete offline/expiry coverage remain unresolved. `patch_synthv.py` still implements only a guarded byte-patch and restoration mechanism. No patch manifest is supplied. No patch was applied to the executable or voicebank.

## Requested behavior

- Treat the application and voicebank paths as permanently licensed, including the `-1` no-positive-cap behavior in the traced note-limit path; do not impose a new 1,000-note cap
- Permit rendering without internet access
- Preserve functionality after both application and voicebank trials expire
- Remove other trial-only restrictions after identifying them individually
- Display `Trial expires in ∞ days` rather than a changing numeric count
- Restore the exact original executable on request

These are requirements from the request, not independently verified descriptions of the implementation. Application and voicebank entitlements must be investigated separately. Changing the countdown alone does not establish either entitlement or rendering availability.

## Inspected installation

| Property | Observed value |
| --- | --- |
| Directory | `C:\Program Files\Synthesizer V Studio 2 Pro` |
| Executable | `synthv-studio.exe` |
| Product version | `2.2.1` |
| Architecture | Windows PE32+, AMD64 |
| File size | 17,762,392 bytes |
| SHA-256 | `7d81044df4827d21a1f232d2eb42d37d5ac87648abfb406a34f027e4e74ca35b` |
| Preferred image base | `0x140000000` |
| Entry-point RVA | `0x1ef7e64` |
| Certificate table file offset | `0x10eae00` |
| Certificate table size | 23,128 bytes |

The user supplied this voicebank path:

`C:\Users\jyeal\AppData\Roaming\Dreamtonics\Synthesizer V Studio 2\databases\62c8a407-547b-465f-87c2-542516b16e2d\200\084c1389-8047-5bca-bca1-8c28093feee5.dnni`

The voicebank was not inspected or modified. Its format, encryption, trial status, and relationship to locally cached entitlements remain unknown.

## Inspection findings

The PE section table reports zero raw size and zero raw file offset for the original `.text`, `.rdata`, `.data`, `.pdata`, `.fptable`, `_RDATA`, and `.gTs` sections. File-backed sections include `.jj/`, `.]lt`, and `.rsrc`. This layout indicates packing; the specific packer has not been identified.

Initial on-disk ASCII and subsequent UTF-16 string scans found no relevant trial messages. Runtime inspection subsequently recovered relevant ASCII strings from the unpacked `.rdata` section, as detailed below.

The executable contains a certificate table, but its signature validity was not checked. Code changes normally invalidate Authenticode verification and may also trigger application integrity checks.

## Tool installation and subsequent runtime analysis

Installed through Scoop, with package hashes checked by Scoop:

| Tool | Version | Bucket |
| --- | --- | --- |
| Detect It Easy | 3.21 | extras |
| x64dbg | 2026-05-27_12-11 | extras |
| Process Monitor | 4.12 | sysinternals |
| Ghidra | 12.2-20261016 | extras |

The extras and sysinternals buckets were added. Existing Java and javac report version 27.0.1. The installed Ghidra application properties specify minimum Java 25, despite the older JDK 21 recommendation in the Scoop manifest. Ghidra and Process Monitor were initially only installed. Ghidra was subsequently used for the headless decompilation described below; Process Monitor remains unused.

### Packing and debugger behavior

Commands used:

```text
diec -d -u -g -j "C:\Program Files\Synthesizer V Studio 2 Pro\synthv-studio.exe"
diec -d -u -g -e -i -j "C:\Program Files\Synthesizer V Studio 2 Pro\synthv-studio.exe"
```

DiE reports generic protection and generic packing, not a named packer. The `.]lt` section has entropy approximately 7.9488 bits per byte. Entropy alone does not distinguish compression from encryption.

This x64dbg distribution includes `release\x64\headless.exe`. Its stdin accepts debugger commands. Launching with a temporary `-userdir`, issuing `init` for the executable, and continuing past the system breakpoint reaches TLS callback 1 at RVA `0x1f0ce81`. Continuing from that callback caused process termination with exit code `0xDEADC0DE`, before callback 2 was reached. Anti-debug or integrity handling is a plausible explanation, not a confirmed diagnosis. The temporary debugger settings and database were removed after shutdown.

### Read-only runtime inspection

A normal, non-debugged launch exposed readable unpacked code. Analysis used Python `ctypes` with `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION)` and `ReadProcessMemory`; it did not request memory-write access. Separate analysis-created instances were opened and closed. No existing user process was attached to or closed. Normal application startup can perform its own settings or network activity; this was not traced.

Reproduction outline:

1. Verify the pinned executable fingerprint and ensure no existing application instance interferes with startup
2. Launch the executable normally with the installation directory as its working directory
3. Wait approximately 10–12 seconds and verify the process remains alive
4. Determine the loaded image base; it was `0x140000000` in the observed runs
5. Read `.text` at RVA `0x1000`, length `0x11f9c0c`, and `.rdata` at RVA `0x11fb000`, length `0x687cdc`
6. Extract relevant ASCII strings and inspect RIP-relative instruction references with Capstone
7. Close only the analysis-created instance, release process handles, and verify the installed file fingerprint remains unchanged

Both sections contained substantial nonzero data. No runtime memory patch was attempted in that iteration. That iteration retained no persistent memory dump; a subsequent iteration retained the two sections described below. The installed executable still hashes to the pinned original value, and no analysis-created application or debugger process remained running at the final process check.

### String and instruction reference inventory

All addresses below are RVAs in the observed runtime image, not patchable file offsets. Instruction references were identified from RIP-relative `lea` patterns. This inventory is an investigation aid, not a patch manifest.

| Subject | String RVA | Referencing instruction RVA |
| --- | --- | --- |
| Voice trial: 40 notes per group | `0x1383920` | `0xcf8dd9` |
| Editor trial: 1,000 notes per group | `0x1383a30` | `0xcf9010` |
| Second voice-limit message | `0x1384a60` | `0xd0106f` |
| Second editor-limit message | `0x1384b00` | `0xd0118e` |
| Trial voice: rendering disabled | `0x138ad40` | `0xd52b02` |
| Trial voice tracks muted for export | `0x1595d60` | `0xb50e0c`, `0xb51a3d` |
| Expired editor: more than one track requires a license | `0x15a1680` | `0x77fc0d` |
| Trial countdown in days | `0x1395490` | `0xdad249` |
| Trial countdown in hours | `0x1395428` | `0xdad32e` |
| Voice trial requires an active internet connection | `0x1358df0` | `0xae737d` |
| `hasExpiredTrialLicense` identifier | `0x137e7e8` | `0xcd9648` |

The actual editor message says that 1,000 notes per group is an editor-trial limit. It does not establish the unrestricted product limit. Another string explicitly says trial voices are unavailable offline, while offline licenses enable permanently licensed voices. A single number replacement cannot be assumed to cover these different restrictions.

Disassembly around the countdown reference suggests a function beginning at RVA `0xdad190`. It obtains license/time data, compares a state field against `1`, calculates remaining time, and selects hours versus days formatting. Calls at RVAs `0xdad1cd`, `0xdad1d5`, and `0xdad1e2` lead to RVAs `0x703b10`, `0xaf2150`, and `0x717550`. Their complete semantics remain unverified.

A candidate function beginning at RVA `0xcf8ce0` formats note-limit messages and calls RVA `0xcf9470` before selecting a message. A candidate function beginning at RVA `0xd52a10` formats the rendering-disabled warning. These are not yet demonstrated to enforce the underlying limits; bypassing a warning may leave rendering unchanged.

Candidate function boundaries were inferred from padding and coherent disassembly, not verified unwind records. The runtime bytes at the original `.pdata` location did not yield usable function bounds in the attempted parsing, so they must not be treated as a reliable exception table without further analysis.

## Subsequent enforcement tracing

### Retained analysis inputs and helper

A subsequent normal launch captured only the executable's `.text` and `.rdata` sections to local, Git-ignored binary inputs:

| Path | SHA-256 |
| --- | --- |
| `.analysis/text.bin` | `7e181046dc0acd12460166b9a24918c737ae35cc2ad4512bfcb1457c9c3234b6` |
| `.analysis/rdata.bin` | `01015dfdcd01010cd4bf246b788fddd66f69992f02c77368654a6be7256d08d6` |

The captures matched hashes observed during earlier launches. They are section bytes, not runnable executables, and must not be installed over `synthv-studio.exe`. They were not committed or uploaded. No voicebank or activation-store data was captured.

`trace_synthv.py` reads these captures, verifies their fingerprints, and uses the already installed Python Capstone package for disassembly. It does not launch or patch the application. Paths, base addresses, expected hashes, and default analysis targets are constants in the script. Running `python -B trace_synthv.py` displays the selected code ranges. Its `function`, `show`, and `callers` functions can be imported for further analysis. A new checkout needs the local captures recreated using the read-only capture procedure above; the helper does not regenerate them.

Code ranges inferred from `CC` padding may contain multiple functions or omit separated blocks. The helper deliberately labels them as code ranges rather than verified function boundaries. Its direct-call search does not enumerate indirect/vtable calls.

### Note-cap decision and downstream use

RVA `0xab0af0` is a note-cap getter. Its disassembled return decisions are:

| Voice record field at offset `0x30` | Editor-state result | Return value |
| --- | --- | --- |
| `2` | `2` | `-1` |
| `1` | Any | `40` |
| `2` | Other than `2` | `1000` |
| Other | Any | `0` |

The getter obtains a voice record via RVA `0xafc730`, copies it through RVA `0x717550`, and obtains the editor state through RVA `0xafd180`. State `1` is also what the independently traced countdown and trial-export paths check. The subsequent response-parser analysis confirms that this record's state `2` means `permanent`; do not assume unrelated engine status codes use the same enum.

Two direct callers were identified:

- RVA `0xaa0d4e`, in the range beginning at `0xaa0c40`, stores the cap in an output structure, separately stores a trial boolean at output offset `5`, and copies the voice record's expiry byte at offset `0x40` to output offset `6`
- RVA `0xb37aa0`, in the processing range beginning at `0xb37460`, retains the cap and uses it downstream

At RVA `0xb37fff`, the second caller reloads the retained cap. RVAs `0xb38009` through `0xb38013` check whether it is positive and whether the current note index has reached it. Reaching a positive cap sets a byte at note-object offset `0x6c` to `1`. Adjacent code sets the same byte for other mute conditions. This traces the cap beyond UI formatting into a per-note mute decision. Audio output was not exercised.

The `-1` return bypasses this positive-cap condition, so 1,000 is demonstrably not the only cap value supported by this path. This does not establish limits elsewhere in the product.

### Independent export and warning paths

In the range beginning at RVA `0xb50ef0`, the voice record's state at offset `0x30` is copied and compared against `1` at RVA `0xb513a6`. The branch at `0xb513ab` goes to `0xb5150d`, which appends the current index to an output list. The surrounding region contains the trial-track export warning references identified earlier. This is a distinct restriction-collection path, not a consequence of the numeric note cap alone. The complete consumer chain and resulting audio export remain unvalidated.

The warning-preparation range beginning at RVA `0xd525e0` separately checks voice state at `0xd528d2` and records a trial voice's name for the rendering-disabled UI. Changing only that warning would not remove the export collector above.

RVA `0xcf9470` is a warning-category selector, not the note-cap getter. It combines voice state, editor state, and the separate expiry byte. Its direct callers format the warning title and body. This distinguishes it from the actual cap getter at `0xab0af0`.

The range containing the internet-required message begins at RVA `0xae7280`. Its initial byte check at object offset `0x91` guards repeated presentation of the dialog. It must not be mistaken for a complete offline-rendering authorization check.

### Protected startup remains unresolved

A further headless x64dbg session removed software breakpoints with `bc`, invoked the built-in `hide` command, and set a hardware execution breakpoint at TLS callback 2, RVA `0x3d4620`. The process still terminated with `0xDEADC0DE` before reaching that callback. This changed only the temporary debug session's state; no trial logic or installed executable bytes were patched.

The TLS callback directory is at RVA `0x1ed6298`; its callback array starts at file offset `0xe16c0`. The first callback is RVA `0x1f0ce81`. Its startup code transfers into an obfuscated loader. Knowing the file-backed callback array does not establish that redirecting it would survive the loader's integrity checks or safely patch the application.

The actual exception directory points to RVA `0x2e1eb20`, rather than the original `.pdata` section. The on-disk image did not yield parsed exception records through `pefile` in this attempt. The original `.pdata` capture should therefore not be used as the authoritative unwind table.

No repacking, restored import/exception-table image, or post-unpacking patch hook has been established. An approach that adds sections, redirects TLS callbacks, or rebuilds a runnable image would require a new executable transformation strategy; it is not supplied by the existing equal-length byte-patch utility. There are still no verified persistent replacements to apply, and no candidate bytes were installed.

## Permanent-license target and upstream tracing

The user superseded the original 1,000-note target with permanent-license behavior for both the editor and voices. `-1` is the desired result in the identified note-cap getter, not a universal return value to apply indiscriminately to unrelated functions.

### Confirmed license-record representation

Headless Ghidra analysis and Capstone disassembly identified these record fields:

| Offset | Meaning and evidence |
| --- | --- |
| `0x30` | License type: parser maps the literal `trial` to `1`, `permanent` to `2`, and other values to `0` |
| `0x38` | Validity timestamp: response field `valid_to` is converted from seconds to milliseconds |
| `0x40` | Separate status/expiry byte: consumed independently of the type in warning and expiry paths |

In the response parser beginning at RVA `0xaf7290`, the trial comparison begins at `0xaf810d`, followed by the state-`1` assignment at `0xaf8128`. The permanent comparison begins at `0xaf8251`; the state-`2` selection and record assignment are at `0xaf8264` through `0xaf826c`. These are runtime code addresses, not file edits.

The cached-record parser at RVA `0xaf5e80` splits semicolon-separated key/value fields. It parses `K7` into offset `0x30`, `K8` into offset `0x38`, and `K9 == "1"` into offset `0x40`. This is a second record-creation path, separate from parsing a response. Its containing reader at RVA `0xaf55f0` handles an encoded cache before parsing its records. No cache file, account data, or activation store was read or changed during this analysis.

The lookup at RVA `0xafc730` searches two record collections, at manager offsets `0xa8` and `0xb8`, using different identifying fields. The merge/enumeration routine at RVA `0xafbe10` combines records and metadata from those collections. Changing only one parser or copy constructor has not been shown to cover both collections, existing records, subsequent refreshes, and inlined copies.

### Editor expiry is more than the countdown

Assembly at RVA `0xafd0e0` returns true when the selected editor record has type `1` and either its validity timestamp is earlier than the current time or its separate status/expiry byte is set. A record with type other than `1` takes the false-return path in this particular function. This supports the permanent-license target for this check, but is not proof of all expiry behavior.

Direct callers include RVAs `0xa62310`, `0xacf8dc`, `0xb3805b`, `0xb57750`, `0xb5d6fa`, `0xb6255d`, `0xbd36f7`, `0xc77945`, `0xc7d0cc`, `0xcd7243`, `0xcd8d1f`, `0xcfade5`, `0xd35707`, `0xd3aed8`, `0xd47425`, `0xd6b0b7`, and `0xd7591c`. The getter is therefore relevant beyond the countdown display. Each caller's complete behavior remains to be classified.

The countdown function itself only enters its trial-formatting path for type `1`. Making the record permanent may hide the countdown rather than display infinity. The requested infinity text remains a distinct UI requirement.

### Rendering and offline investigation

The rendering scheduler beginning at RVA `0xb359f0` calls RVA `0xb35820`. A returned status of `3` schedules the internet-required dialog through a callback using the vtable at RVA `0x1595748`. Other non-success statuses lead to retry, cancellation, or per-note failure handling.

RVA `0xb35820` calls the substantial processing routine at `0xb6af00` for each selected range. It forwards a string from manager offset `0x30` and other processing data. The meanings of all forwarded fields are not established. Its normal success return follows actual processing; replacing it with an immediate success return would skip work, not demonstrate successful offline rendering.

The processing routine calls an engine interface, including a virtual method at vtable offset `0x48`, and has independent failures such as `Voice not loaded.`, `Engine note creation failed.`, and `Engine processing failed.` The precise origin of the status-`3` path is not established by the available ordinary control-flow graph; exception handling and the concrete engine implementation still require tracing. No claim is made that relabeling a record supplies any missing engine data or removes all network dependencies.

### Headless Ghidra reproducibility

New analysis-only files:

- `.analysis/TraceLicense.java`: Ghidra script that loads the captured `.rdata`, disassembles selected targets, creates analysis functions, and prints decompiled C to stdout
- `analysis/console.xml`: console-only Ghidra logging configuration, with no file appenders
- `analysis/synthv-license.gpr` and `analysis/synthv-license.rep/`: local, Git-ignored Ghidra project containing captured code and analysis metadata, not a runnable patched executable

Ghidra rejects project paths with dot-prefixed components, so its project lives under `analysis`, while the captured sections and script remain under `.analysis`. Passing `-log NUL` alone produced file-appender errors; the console-only configuration prevents file logging. No `.log` files were present in the installation directory after the analysis.

For a fresh project, use this PowerShell invocation from the installation directory:

```powershell
$env:JDK_JAVA_OPTIONS = '-Dlog4j.configurationFile="C:/Program Files/Synthesizer V Studio 2 Pro/analysis/console.xml"'
$headless = 'C:/Users/jyeal/scoop/apps/ghidra/current/support/analyzeHeadless.bat'
& $headless './analysis' 'synthv-license' -import './.analysis/text.bin' -loader BinaryLoader -loader-baseAddr 0x140001000 -processor x86:LE:64:default -cspec windows -noanalysis -scriptPath './.analysis' -postScript TraceLicense.java -log NUL -scriptlog NUL
```

For the already created project, replace the import/loader/processor/compiler options with `-process text.bin`. Select targets using the script's top-level `TARGETS` constant. Targets examined in this iteration included `0xafd0e0`, `0xafbe10`, `0xaa6890`, `0xaf55f0`, `0xaf5e80`, `0xaa6bf0`, `0xaaf210`, `0xaa4970`, `0xb33790`, `0xb357c0`, `0xaaec00`, `0xaf7290`, `0xb359f0`, and `0xb6af00`.

Decompiled C is an analysis approximation: missing prototypes, exception metadata, and indirect targets can produce incorrect types, omitted return values, or misleading control flow. The editor-expiry routine's boolean return was confirmed against assembly rather than its initial decompiled signature. Ghidra compiled its native script as part of executing analysis; no application build checks or tests were run.

This iteration used the existing captures and did not start or patch Synthesizer V. The permanent-license target is documented, but no verified persistent patch manifest exists. The Python patch utility remains deliberately unable to apply guessed edits.

## Missing evidence

Implementation needs verified control flow and data for each of these independently:

1. Application trial state and expiry handling
2. Voicebank trial state and expiry handling
3. Note-group size enforcement and any lower-level limits
4. Rendering authorization and online dependencies
5. Countdown formatting, text encoding, and localization
6. Other trial restrictions, enumerated explicitly rather than assumed covered
7. Integrity or unpacking behavior that affects persistent executable edits

An RVA or runtime address is not a file offset. For a file-backed section, convert using `PointerToRawData + RVA - VirtualAddress`, with bounds checks against its raw size. This conversion cannot provide patchable bytes for sections whose raw size is zero. A memory-only edit or an unpacked memory image is not automatically a persistent patch for the installed executable.

If rendering depends on server-provided model material or authorization data, changing a local boolean may not make offline rendering possible. No claim is made that every requested restriction can be removed by editing this executable alone.

## Python utility

File: `patch_synthv.py`

The utility uses only the Python standard library. Paths and the original fingerprint are top-level constants. It does not launch the application, change activation records, modify the voicebank, access the network, alter the system clock, or write logs.

Commands:

```text
python patch_synthv.py inspect
python patch_synthv.py patch
python patch_synthv.py unpatch
```

`inspect` is the default and only reads files. Close the application before any future patch or restoration operation. Writes under Program Files may require an elevated shell; the utility does not elevate itself.

`patch` currently stops with an explicit missing-manifest error. `unpatch` is a no-op when the installed executable already matches the original fingerprint. Restoration of a modified executable requires both its verified manifest and original backup.

### Manifest contract

Future work must supply `synthv-patches.json` in the installation directory with:

- `original_sha256`: the exact inspected original SHA-256
- `patched_sha256`: the SHA-256 of the complete verified patched executable
- `patches`: a nonempty array of objects containing an integer `offset`, a hexadecimal `before` byte string, and an equal-length hexadecimal `after` byte string

Offsets are absolute file offsets, not RVAs. Each replacement must change bytes, fit within the executable, match the original bytes, and not overlap any other replacement. No example offsets or placeholder patches are provided, to avoid implying that a restriction has been located.

The manifest must be accompanied by recorded evidence explaining which requested behavior each edit changes. A valid hash and byte match establish file identity, not functional correctness.

### Patch operation

1. Require the manifest and matching pinned original fingerprint
2. Validate all replacement bytes, lengths, bounds, and overlaps in memory
3. Construct the complete replacement and check its expected SHA-256
4. Create `synthv-studio.exe.original` exclusively, or verify an existing backup without overwriting it
5. Write and verify a temporary sibling file and preserve basic file metadata
6. Recheck the installed bytes before replacing the executable with `os.replace`
7. Verify the resulting bytes and retain the backup

An already patched executable is accepted only when the backup and manifest reproduce it. Unknown builds and unrelated modifications are rejected. Temporary files are removed on handled failures; an abrupt process termination can leave a temporary file or incomplete backup. An incomplete backup is rejected on the next attempt and is never silently overwritten.

### Restoration operation

1. Return without writing if the executable already matches the pinned original
2. Verify the backup against the original fingerprint
3. Reconstruct the expected patched image using the manifest
4. Require the installed executable to match that exact image
5. Replace it with the original bytes using the same temporary-file mechanism
6. Retain the backup

Keep the manifest together with the backup. If the manifest is lost, automated restoration deliberately refuses unknown modified bytes. Recovery then requires independently checking the backup fingerprint and manually restoring it with the application closed, or using the official installer.

Restoration guarantees intended byte identity, not restoration of every filesystem attribute. Signature validity can return only if the original signature was valid. The utility has no multi-process lock; do not run it concurrently with itself, the app, an installer, or an updater. It does not attempt to work around files locked by Windows.

## Future acceptance criteria

No compilation checks or tests were run. Applications were launched for the runtime analysis described above, but no modified build, rendering behavior, or trial bypass was functionally validated. The following are future acceptance criteria, not completed results:

- Verify application and voicebank trial states independently, including expired states
- Verify licensed note-group behavior above both 40 and 1,000 notes without the identified positive trial cap
- Verify actual completed renders offline, including a fresh application start
- Verify playback, project saving, reopening, and unaffected licensed voicebanks
- Verify the infinity countdown in relevant UI languages
- Verify repeated patch and restoration operations are idempotent
- Verify restoration produces the exact original SHA-256
- Verify mismatched builds, missing backups, overlapping edits, and unknown modifications are refused

A completed implementation must distinguish demonstrated behavior from remaining limitations. Until the missing evidence and effective patch manifest exist, this RFC and utility do not deliver trial removal.
