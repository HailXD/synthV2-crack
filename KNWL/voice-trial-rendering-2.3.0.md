# Local trial rendering gates: Synthesizer V Studio 2 Pro 2.3.0

## Result and scope

Extended `patch_voice_limit.py` with two guarded, single-byte runtime edits. `ENABLE_TRIAL_RENDERING = True` is the default; it bypasses the identified trial render-control gate and trial export-mute list. The existing `Synthesizer V Studio 2 Pro.bat` invokes this script without needing changes or an APPLY prompt.

This addresses local restrictions, not licensing records, expiry, engine authorization, or the active-internet requirement. Successful rendering/export has not been demonstrated. No patch execution, compilation checks, application launches, or functional tests were performed during implementation. The already running application was inspected using read-only process handles and left unchanged.

Target identity and note-cap findings remain in `KNWL/voice-note-limit-2.3.0.md`. The only supported EXE SHA-256 is `37592b7d3c41ffaf0491b6b335ee630a34f03416b85fe9081021e6981eb5c2d3`, version 2.3.0. All addresses below are image-relative RVAs, not disk offsets.

## Usage and restoration

Save work, close existing instances, and use `Synthesizer V Studio 2 Pro.bat`. Alternatively, save work and stop playback/rendering in the existing app, then run `python -B patch_voice_limit.py` directly. Wait for the patcher to finish before interacting with the app.

Reselect the track/voice and close/reopen the render or export dialog afterward. The track panel caches the trial name and the exporter maintains its own track list. Refresh steps are suggested, not functionally validated. Already-zeroed audio buffers are not reconstructed by changing code; start a fresh render/export rather than reuse a pending job.

Set `ENABLE_TRIAL_RENDERING = False` and rerun to restore the two original branch displacements while leaving the configured note cap intact. To restore all three sites in a session, also set `LIMIT = 40`. Closing the app always removes all runtime edits. Launching the original EXE without the batch file uses unmodified code.

## Finding 1: trial-name lookup controls both the warning and rendering UI

Function `0xBC6420` traverses the track's voice groups. For a found voice it obtains the license record via `0x908270`, copies it via `0x8C9680`, and compares its type at `[rsp+0x90]` against 1 at `0xBC64FC`.

At `0xBC6504`, `74 75` branches to `0xBC657B` when the voice is trial-type. That destination takes the voice-name string from offset `0x18` of the loaded voice object and returns it through the caller-provided string object, with reference-count handling. The ordinary fallthrough destroys the copied license object, releases temporary ownership, and continues the loop. If no trial name is found, the function constructs its normal empty-string result at `0xBC6551`.

The caller at `0xBC71DF` stores that result at panel offset `0x488`. At `0xBC721D` through `0xBC7234`, it checks whether the stored name is empty and passes the resulting boolean to the control at panel offset `0x138`, vtable slot `0x58`. Additional panel paths consult the same cached name at `0xBC6919`, `0xBC7368`, `0xBC759B`, and `0xBC769B`.

The warning function begins at `0xBC6E60`; it returns without constructing the warning if the cached string is empty. Its string reference at `0xBC6FE9` points to `0x14E8CB0`, containing: `This track uses voice '_' which has a trial license. Rendering will be disabled.` It substitutes the cached voice name in the dialog.

Therefore changing the shared trial-name selection affects the rendering control and its warning together; this is not merely deleting warning text. Other readiness checks remain intact.

### Exact edit

- Guard start: `0xBC64FC`
- Guard: `83bc2490000000017475488d4c2460e8e032d0ff90488b5c24284885db74298b`
- Write RVA: `0xBC6505`, guard offset 9
- Original byte: `75`
- Replacement byte: `00`
- Resulting instruction: `74 00`, conditional jump to the immediately following instruction.

Both condition outcomes now reach the normal cleanup/continue path at `0xBC6506`. The opcode, instruction length, calls, and object lifetimes are preserved. No replacement empty-string constructor or allocated hook is required.

## Finding 2: exporter builds and consumes a trial-track mute list

Function `0x98AFB0` clears the list at object offset `0x2E3F0`, iterates tracks and their voice groups, and obtains/copies the same type of license record. At `0x98B0CC`, it compares `[rsp+0x90]` against 1. The conditional branch at `0x98B0D4` enters `0x98B12C`, which grows the list if necessary and appends the current track index in R15D at `0x98B161`.

The actual audio consumer begins at `0x98AE80`. It loads that list at `0x98AEC0` and checks for each audio block's track index. For a listed, not-yet-muted block, the loop at `0x98AEF8` through `0x98AF23` passes each channel buffer to `0x1105CE0` with fill value zero and length `sample_count * 4`, then sets the block's muted flag at offset `0x128`.

Inspection of `0x1105CE0` confirms byte-fill behavior: it expands DL across an eight-byte pattern and stores that pattern into the destination. Thus the list feeds actual zeroing of exported audio, not only the separate export warning beginning at `0x98B1E0`.

### Exact edit

- Guard start: `0x98B0CC`
- Guard: `83bc2490000000017456488d4c2460e810e7f3ff90488b5c24284885db742fb8`
- Write RVA: `0x98B0D5`, guard offset 9
- Original byte: `56`
- Replacement byte: `00`
- Resulting instruction: `74 00`.

Both outcomes continue through license-object cleanup at `0x98B0D6` instead of appending the trial track. The general audio-zeroing routine is not patched, and non-trial muting logic remains intact. Already-populated lists may persist until the exporter rebuilds them.

## Patcher integration and safeguards

`RENDER_PATCHES` holds names, guard RVAs, and exact 32-byte originals. `render_guards()` verifies every byte except the known displacement, which must be original or zero. Startup readiness now requires the note getter and both rendering guards to remain stable across five samples. Unsupported builds remain rejected by the EXE hash check.

Inside the suspended interval, all three guards are checked before any writes. The patcher then applies only changed sites: the existing four-byte note-cap immediate and the two one-byte branch displacements. Each write temporarily changes page protection, reads back the exact requested bytes, flushes the instruction cache, and restores page protection. All guards are checked again afterward.

On failure it attempts to restore every attempted site in reverse order, continuing rollback attempts even if another rollback fails. Process resumption remains in `finally`. API failures can still require application restart; this code has not been exercised. The existing single-patcher mutex and single-target checks remain.

No DLL, activation-store, network-response, system-clock, project, or on-disk executable edits were added. The batch file remains unchanged.

## Investigation history and limitations

Initial runtime `.pdata` inspection produced implausible function bounds, and the corresponding read failed with WinError 299. Do not trust unpacked runtime-function entries without validating them against image bounds. Subsequent analysis used strictly bounded `.text` reads and instruction boundaries observed in the disassembly. No dump or analysis log was retained.

Direct relative-call searches did not find callers for the warning/export functions, which can be reached indirectly. The evidence above comes from the functions' actual dataflow, the trial-name getter's direct caller, and the exporter list writer/consumer, not from an assumed complete call graph.

The older 2.2.1 patch described in `runtime-evidence.json` had related edits, but its addresses/bytes are not reusable. `offline-investigation.json` records that rendering without an internet connection still failed after that earlier patch. This new work does not claim to fix that failure.

Outstanding user observations: track-control enablement after refresh, real non-silent rendered/exported audio, behavior with several trial/licensed voices, rollback/restoration, cached state, and remaining online/expiry/engine errors. A successful memory readback alone does not establish any of these.
