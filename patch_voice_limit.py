import ctypes as ct
from ctypes import wintypes as wt
import hashlib
import os
from pathlib import Path
import struct
import time


APP_PATH = Path(r"C:\Program Files\Synthesizer V Studio 2 Pro\synthv-studio.exe")
EXPECTED_SHA256 = "37592b7d3c41ffaf0491b6b335ee630a34f03416b85fe9081021e6981eb5c2d3"
LIMIT = -1
SUPPORTED_LIMITS = (-1, 9999, 40)
ENABLE_TRIAL_RENDERING = True
RENDER_PATCHES = (
    ("trial render control", 0xBC64FC,
     bytes.fromhex("83bc2490000000017475488d4c2460e8e032d0ff90488b5c24284885db74298b")),
    ("trial export mute list", 0x98B0CC,
     bytes.fromhex("83bc2490000000017456488d4c2460e810e7f3ff90488b5c24284885db742fb8")),
)
BRANCH_DISPLACEMENT_OFFSET = 9
FALLTHROUGH_DISPLACEMENT = b"\x00"
GETTER_RVA = 0x8C1EC0
IMMEDIATE_OFFSET = 0x76
ORIGINAL = bytes.fromhex(
    "48895c2408574883ec20488bd9e86ef5f8ff488b5308488bc8488bf8e88f630400"
    "8b483083f9027518488bcfe8cf64040033d2b903000000837830020f44caeb11"
    "83f901754f33d28bca3848400f95c1ffc185c9742f83e901741a83e9017415"
    "83e9017530b8e8030000488b5c24304883c4205fc3b828000000488b5c2430"
    "4883c4205fc3b8ffffffff488b5c24304883c4205fc3488b5c243033c04883c4205fc3"
)
IMMEDIATE_SIZE = 4
PID_CAPACITY = 8192
MODULE_CAPACITY = 2048
PATH_CAPACITY = 32768
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ACCESS = 0x400 | 0x10 | 0x20 | 0x08 | 0x800 | 0x100000
LIST_MODULES_ALL = 3
PAGE_EXECUTE_READWRITE = 0x40
ERROR_ALREADY_EXISTS = 183
MUTEX_NAME = r"Local\SynthV230VoiceNoteLimitPatch"
STARTUP_TIMEOUT_SECONDS = 60
POLL_SECONDS = 0.5
STABLE_SAMPLES = 5
STILL_ACTIVE = 259
WAITING_MESSAGE = "Waiting for a visible, idle application window."


def bind(library, name, result, *arguments):
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


def require(result):
    if not result:
        raise ct.WinError(ct.get_last_error())
    return result


class Windows:
    def __init__(self):
        kernel = ct.WinDLL("kernel32", use_last_error=True)
        native = ct.WinDLL("ntdll")
        user = ct.WinDLL("user32", use_last_error=True)
        pointer = ct.c_void_p
        size = ct.c_size_t
        self.open = bind(kernel, "OpenProcess", wt.HANDLE, wt.DWORD, wt.BOOL, wt.DWORD)
        self.close = bind(kernel, "CloseHandle", wt.BOOL, wt.HANDLE)
        self.pids = bind(kernel, "K32EnumProcesses", wt.BOOL,
                         ct.POINTER(wt.DWORD), wt.DWORD, ct.POINTER(wt.DWORD))
        self.path = bind(kernel, "QueryFullProcessImageNameW", wt.BOOL,
                         wt.HANDLE, wt.DWORD, wt.LPWSTR, ct.POINTER(wt.DWORD))
        self.modules = bind(kernel, "K32EnumProcessModulesEx", wt.BOOL,
                            wt.HANDLE, ct.POINTER(wt.HMODULE), wt.DWORD,
                            ct.POINTER(wt.DWORD), wt.DWORD)
        self.read = bind(kernel, "ReadProcessMemory", wt.BOOL,
                         wt.HANDLE, pointer, pointer, size, ct.POINTER(size))
        self.write = bind(kernel, "WriteProcessMemory", wt.BOOL,
                          wt.HANDLE, pointer, pointer, size, ct.POINTER(size))
        self.protect = bind(kernel, "VirtualProtectEx", wt.BOOL,
                            wt.HANDLE, pointer, size, wt.DWORD, ct.POINTER(wt.DWORD))
        self.flush = bind(kernel, "FlushInstructionCache", wt.BOOL,
                          wt.HANDLE, pointer, size)
        self.suspend = bind(native, "NtSuspendProcess", wt.LONG, wt.HANDLE)
        self.resume = bind(native, "NtResumeProcess", wt.LONG, wt.HANDLE)
        self.mutex = bind(kernel, "CreateMutexW", wt.HANDLE,
                          pointer, wt.BOOL, wt.LPCWSTR)
        self.exit_code = bind(kernel, "GetExitCodeProcess", wt.BOOL,
                              wt.HANDLE, ct.POINTER(wt.DWORD))
        self.input_idle = bind(user, "WaitForInputIdle", wt.DWORD, wt.HANDLE, wt.DWORD)
        self.window_callback = ct.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
        self.windows = bind(user, "EnumWindows", wt.BOOL, self.window_callback, wt.LPARAM)
        self.visible = bind(user, "IsWindowVisible", wt.BOOL, wt.HWND)
        self.window_pid = bind(user, "GetWindowThreadProcessId", wt.DWORD,
                               wt.HWND, ct.POINTER(wt.DWORD))

    def image_path(self, process):
        buffer = ct.create_unicode_buffer(PATH_CAPACITY)
        length = wt.DWORD(len(buffer))
        require(self.path(process, 0, buffer, ct.byref(length)))
        return Path(buffer.value)

    def find_process(self):
        pids = (wt.DWORD * PID_CAPACITY)()
        used = wt.DWORD()
        require(self.pids(pids, ct.sizeof(pids), ct.byref(used)))
        if used.value >= ct.sizeof(pids):
            raise RuntimeError("Process list truncated; refusing to select a process.")
        matches = []
        for pid in pids[:used.value // ct.sizeof(wt.DWORD)]:
            process = self.open(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not process:
                continue
            try:
                if self.image_path(process) == APP_PATH:
                    matches.append(pid)
            except OSError:
                pass
            finally:
                self.close(process)
        if len(matches) > 1:
            raise RuntimeError(
                f"Expected one running instance at {APP_PATH}; found {len(matches)}. "
                "Close extra instances before running the patcher."
            )
        return matches[0] if matches else None

    def has_window(self, pid):
        matches = []

        @self.window_callback
        def visit(window, parameter):
            owner = wt.DWORD()
            self.window_pid(window, ct.byref(owner))
            if owner.value == pid and self.visible(window):
                matches.append(window)
            return True

        require(self.windows(visit, 0))
        return bool(matches)

    def image_base(self, process):
        modules = (wt.HMODULE * MODULE_CAPACITY)()
        used = wt.DWORD()
        require(self.modules(process, modules, ct.sizeof(modules),
                             ct.byref(used), LIST_MODULES_ALL))
        if not used.value or used.value > ct.sizeof(modules) or not modules[0]:
            raise RuntimeError("Cannot determine the main image base.")
        return modules[0]

    def read_bytes(self, process, address, length):
        buffer = ct.create_string_buffer(length)
        transferred = ct.c_size_t()
        require(self.read(process, address, buffer, length, ct.byref(transferred)))
        if transferred.value != length:
            raise RuntimeError("Incomplete memory read.")
        return buffer.raw

    def write_bytes(self, process, address, data):
        buffer = ct.create_string_buffer(data)
        transferred = ct.c_size_t()
        require(self.write(process, address, buffer, len(data), ct.byref(transferred)))
        if transferred.value != len(data):
            raise RuntimeError("Incomplete memory write.")
        if self.read_bytes(process, address, len(data)) != data:
            raise RuntimeError("Memory write readback mismatch.")
        require(self.flush(process, address, len(data)))


def guard(api, process, address):
    current = api.read_bytes(process, address, len(ORIGINAL))
    end = IMMEDIATE_OFFSET + IMMEDIATE_SIZE
    normalized = current[:IMMEDIATE_OFFSET] + ORIGINAL[IMMEDIATE_OFFSET:end] + current[end:]
    value = struct.unpack_from("<i", current, IMMEDIATE_OFFSET)[0]
    if normalized != ORIGINAL or value not in SUPPORTED_LIMITS:
        raise RuntimeError("Runtime code mismatch; no patch applied. Do not reuse older patch addresses.")
    return current, value


def render_guards(api, process, base):
    snapshots = []
    offset = BRANCH_DISPLACEMENT_OFFSET
    for name, rva, original in RENDER_PATCHES:
        current = api.read_bytes(process, base + rva, len(original))
        normalized = current[:offset] + original[offset:offset + 1] + current[offset + 1:]
        if normalized != original or current[offset:offset + 1] not in (
            original[offset:offset + 1], FALLTHROUGH_DISPLACEMENT
        ):
            raise RuntimeError(f"Runtime code mismatch at {name}; refusing to patch.")
        snapshots.append(current)
    return tuple(snapshots)


def wait_ready(api, process, pid, deadline):
    last_sample = None
    stable = 0
    reason = WAITING_MESSAGE
    while time.monotonic() < deadline:
        exit_code = wt.DWORD()
        require(api.exit_code(process, ct.byref(exit_code)))
        if exit_code.value != STILL_ACTIVE:
            raise RuntimeError("Application exited before patching; no patch applied.")
        try:
            if api.input_idle(process, 0) != 0 or not api.has_window(pid):
                raise RuntimeError(WAITING_MESSAGE)
            address = api.image_base(process) + GETTER_RVA
            current, _ = guard(api, process, address)
            rendering = render_guards(api, process, address - GETTER_RVA)
            sample = (address, current, rendering)
            stable = stable + 1 if sample == last_sample else 1
            last_sample = sample
            if stable >= STABLE_SAMPLES:
                return address
            reason = "Waiting for stable matching runtime code."
        except (OSError, RuntimeError) as error:
            reason = str(error)
            last_sample = None
            stable = 0
        time.sleep(POLL_SECONDS)
    raise RuntimeError(f"Startup timed out; no patch applied. {reason}")


def write_protected(api, process, address, data):
    old_protection = wt.DWORD()
    require(api.protect(process, address, len(data),
                        PAGE_EXECUTE_READWRITE, ct.byref(old_protection)))
    try:
        api.write_bytes(process, address, data)
    finally:
        ignored = wt.DWORD()
        if not api.protect(process, address, len(data),
                           old_protection.value, ct.byref(ignored)):
            raise RuntimeError("Page protection restoration failed; restart the app before using it.")


def patch(api, process, address):
    status = api.suspend(process)
    if status < 0:
        raise RuntimeError(f"Cannot suspend target: NTSTATUS {status & 0xFFFFFFFF:#x}")
    try:
        current, previous = guard(api, process, address)
        base = address - GETTER_RVA
        rendering = render_guards(api, process, base)
        changes = [(address + IMMEDIATE_OFFSET,
                    current[IMMEDIATE_OFFSET:IMMEDIATE_OFFSET + IMMEDIATE_SIZE],
                    struct.pack("<i", LIMIT))]
        offset = BRANCH_DISPLACEMENT_OFFSET
        for (_, rva, original), snapshot in zip(RENDER_PATCHES, rendering):
            desired = FALLTHROUGH_DISPLACEMENT if ENABLE_TRIAL_RENDERING else original[offset:offset + 1]
            changes.append((base + rva + offset, snapshot[offset:offset + 1], desired))
        attempted = []
        try:
            for location, before, after in changes:
                if before != after:
                    attempted.append((location, before))
                    write_protected(api, process, location, after)
            guard(api, process, address)
            render_guards(api, process, base)
        except BaseException:
            failures = []
            for location, before in reversed(attempted):
                try:
                    write_protected(api, process, location, before)
                except BaseException as error:
                    failures.append(str(error))
            if failures:
                raise RuntimeError("Rollback failed; close and restart the app before using it. "
                                   + "; ".join(failures))
            raise
        return previous
    finally:
        status = api.resume(process)
        if status < 0:
            raise RuntimeError(
                f"Cannot resume target: NTSTATUS {status & 0xFFFFFFFF:#x}. "
                "The app may be suspended; close it using Task Manager and reopen it."
            )


def main():
    if os.name != "nt" or ct.sizeof(ct.c_void_p) != 8:
        raise RuntimeError("Use 64-bit Python on Windows.")
    if LIMIT not in SUPPORTED_LIMITS:
        raise RuntimeError(f"Set LIMIT to one of {SUPPORTED_LIMITS}.")
    if hashlib.sha256(APP_PATH.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError("Unsupported EXE fingerprint; this patch is only for the inspected 2.3.0 build.")
    api = Windows()
    mutex = require(api.mutex(None, False, MUTEX_NAME))
    already_exists = ct.get_last_error() == ERROR_ALREADY_EXISTS
    try:
        if already_exists:
            raise RuntimeError("Another copy of this patcher is running.")
        print("Waiting for Synthesizer V to start. Do not edit or start playback until patching completes.")
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        pid = api.find_process()
        while pid is None and time.monotonic() < deadline:
            time.sleep(POLL_SECONDS)
            pid = api.find_process()
        if pid is None:
            raise RuntimeError("Startup timed out: no matching application process found.")
        process = require(api.open(PROCESS_ACCESS, False, pid))
        try:
            if api.image_path(process) != APP_PATH:
                raise RuntimeError("Process identity changed; refusing to patch.")
            address = wait_ready(api, process, pid, deadline)
            if api.find_process() != pid:
                raise RuntimeError("Process selection changed; refusing to patch.")
            _, previous = guard(api, process, address)
            label = "unlimited (-1)" if LIMIT == -1 else str(LIMIT)
            print(f"Target: {APP_PATH}\nPID: {pid}\nLocal voice note cap: {previous} -> {label}")
            print("Experimental runtime-only patch; applying automatically.")
            print("Expiry, internet requirements and engine authorization are unchanged.")
            previous = patch(api, process, address)
            print(f"Local voice note-cap immediate: {previous} -> {label}; memory readback verified.")
            rendering_label = "bypassed" if ENABLE_TRIAL_RENDERING else "restored"
            print(f"Local trial render-control and export-mute gates: {rendering_label}; memory readback verified.")
            print("EXE unchanged. Reselect the track/voice and reopen the render/export dialog to refresh cached state.")
            print("Repeat after each app restart. Audio behavior has not been validated.")
        finally:
            api.close(process)
    finally:
        api.close(mutex)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, KeyboardInterrupt) as error:
        raise SystemExit(f"Stopped: {error}")
