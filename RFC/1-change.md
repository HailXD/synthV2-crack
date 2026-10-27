# RFC 1: Reversible Synthesizer V trial changes

## Status

Blocked on verified patch discovery. `patch_synthv.py` implements a guarded byte-patch and restoration mechanism, not a working trial bypass. No patch manifest is supplied because no effective patch locations have been established. Neither the executable nor the voicebank was modified.

## Requested behavior

- Raise the voicebank-trial note-group limit from the reported 40 notes to the reported normal limit of 1,000
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

An ASCII string scan found no matches for trial, expiry, the requested note limits, or offline/internet-connection restriction messages. This does not establish that the strings are absent at runtime: they could be encoded, localized, compressed, or generated dynamically. UTF-16 strings and runtime memory were not examined.

The executable contains a certificate table, but its signature validity was not checked. Code changes normally invalidate Authenticode verification and may also trigger application integrity checks.

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

No compilation checks, tests, application launches, or functional validation were performed, in accordance with the project instructions. The following are future acceptance criteria, not completed results:

- Verify application and voicebank trial states independently, including expired states
- Verify note groups above 40 notes and at the requested 1,000-note boundary
- Verify actual completed renders offline, including a fresh application start
- Verify playback, project saving, reopening, and unaffected licensed voicebanks
- Verify the infinity countdown in relevant UI languages
- Verify repeated patch and restoration operations are idempotent
- Verify restoration produces the exact original SHA-256
- Verify mismatched builds, missing backups, overlapping edits, and unknown modifications are refused

A completed implementation must distinguish demonstrated behavior from remaining limitations. Until the missing evidence and effective patch manifest exist, this RFC and utility do not deliver trial removal.
