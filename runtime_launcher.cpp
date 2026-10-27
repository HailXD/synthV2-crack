#include "runtime_patch.h"
#include <bcrypt.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

inline constexpr DWORD PATH_CAPACITY = 32768;
inline constexpr DWORD HASH_BUFFER_SIZE = 65536;
inline constexpr char HEX_DIGITS[] = "0123456789abcdef";
inline constexpr char DLL_SHA256[] = COMPANION_SHA256;
inline constexpr wchar_t LAUNCHER_MUTEX[] = L"Local\\SynthVRuntimeLauncher.2.2.1";

class Handle {
public:
    HANDLE value = nullptr;
    explicit Handle(HANDLE handle = nullptr) : value(handle) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
};

static void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

static void win_require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(std::string(message) + " (Windows error " + std::to_string(GetLastError()) + ")");
}

static std::wstring module_path(HMODULE module) {
    std::vector<wchar_t> buffer(PATH_CAPACITY);
    const DWORD size = GetModuleFileNameW(module, buffer.data(), PATH_CAPACITY);
    win_require(size && size < PATH_CAPACITY, "Cannot obtain module path");
    return std::wstring(buffer.data(), size);
}

static Handle snapshot(DWORD flags, DWORD pid) {
    for (DWORD attempt = 0; attempt < SNAPSHOT_ATTEMPTS; ++attempt) {
        const HANDLE handle = CreateToolhelp32Snapshot(flags, pid);
        if (handle != INVALID_HANDLE_VALUE) return Handle(handle);
        if (GetLastError() != ERROR_BAD_LENGTH) break;
        Sleep(POLL_MS);
    }
    win_require(false, "Cannot enumerate processes, modules or threads");
    return Handle();
}

static MODULEENTRY32W find_module(DWORD pid, const std::wstring& path) {
    const auto modules = snapshot(TH32CS_SNAPMODULE, pid);
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    win_require(Module32FirstW(modules.value, &entry), "Cannot enumerate target modules");
    do {
        if (_wcsicmp(entry.szExePath, path.c_str()) == 0) return entry;
    } while (Module32NextW(modules.value, &entry));
    throw std::runtime_error("Required module is not loaded in the new process");
}

static void require_no_existing_app() {
    const auto processes = snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    win_require(Process32FirstW(processes.value, &entry), "Cannot enumerate processes");
    do {
        require(_wcsicmp(entry.szExeFile, TARGET_NAME) != 0,
                "Close Synthesizer V first; existing processes will not be attached to or changed");
    } while (Process32NextW(processes.value, &entry));
    require(GetLastError() == ERROR_NO_MORE_FILES, "Process enumeration was incomplete");
}

static std::string fingerprint(HANDLE file) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0,
            "Cannot initialize SHA-256");
    try {
        require(BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0,
                "Cannot create SHA-256 state");
        BYTE buffer[HASH_BUFFER_SIZE];
        DWORD size = 0;
        for (;;) {
            win_require(ReadFile(file, buffer, sizeof(buffer), &size, nullptr), "Cannot read executable");
            if (!size) break;
            require(BCryptHashData(hash, buffer, size, 0) >= 0, "Cannot hash executable");
        }
        BYTE digest[32];
        require(BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0, "Cannot finish SHA-256");
        BCryptDestroyHash(hash);
        hash = nullptr;
        BCryptCloseAlgorithmProvider(algorithm, 0);
        algorithm = nullptr;
        std::string result;
        for (BYTE byte : digest) {
            result += HEX_DIGITS[byte >> 4];
            result += HEX_DIGITS[byte & 15];
        }
        return result;
    } catch (...) {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        throw;
    }
}

class Session {
public:
    Handle job{CreateJobObjectW(nullptr, nullptr)};
    HANDLE process = nullptr;
    HANDLE main_thread = nullptr;
    DWORD pid = 0;
    bool complete = false;

    Session() {
        win_require(job.value != nullptr, "Cannot create startup safety job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        win_require(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
                    "Cannot configure startup safety job");
    }
    ~Session() {
        if (process && !complete) {
            TerminateProcess(process, ERROR_PROCESS_ABORTED);
            WaitForSingleObject(process, PATCH_TIMEOUT_MS);
        }
        if (main_thread) CloseHandle(main_thread);
        if (process) CloseHandle(process);
    }
    void start(const std::wstring& path, const std::wstring& directory) {
        std::wstring command = L"\"" + path + L"\"";
        STARTUPINFOW startup = {};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION child = {};
        win_require(CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE,
                                  CREATE_SUSPENDED, nullptr, directory.c_str(), &startup, &child),
                    "Cannot start Synthesizer V");
        process = child.hProcess;
        main_thread = child.hThread;
        pid = child.dwProcessId;
        win_require(AssignProcessToJobObject(job.value, process), "Cannot protect the new process during patching");
        win_require(ResumeThread(main_thread) != static_cast<DWORD>(-1), "Cannot resume application startup");
    }
    void check_alive() const {
        require(WaitForSingleObject(process, 0) == WAIT_TIMEOUT, "The new Synthesizer V process exited");
    }
    void release() {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
        win_require(SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
                    "Cannot release startup safety job");
        complete = true;
    }
};

static bool guards_match(HANDLE process, uintptr_t base) {
    for (const auto& spec : PATCHES) {
        BYTE expected[GUARD_SIZE];
        BYTE actual[GUARD_SIZE];
        SIZE_T size = 0;
        decode_bytes(spec.before, expected, GUARD_SIZE);
        if (!ReadProcessMemory(process, reinterpret_cast<void*>(base + spec.rva), actual, GUARD_SIZE, &size)
            || size != GUARD_SIZE || !equal_bytes(actual, expected, GUARD_SIZE)) return false;
    }
    return true;
}

static uintptr_t wait_for_unpack(Session& session, const std::wstring& target) {
    const ULONGLONG deadline = GetTickCount64() + STARTUP_TIMEOUT_MS;
    DWORD stable = 0;
    uintptr_t base = 0;
    while (GetTickCount64() < deadline) {
        session.check_alive();
        if (!base && WaitForInputIdle(session.process, 0) == 0)
            base = reinterpret_cast<uintptr_t>(find_module(session.pid, target).modBaseAddr);
        if (base && guards_match(session.process, base)) {
            if (++stable >= STABLE_SAMPLES) return base;
        } else {
            stable = 0;
        }
        Sleep(POLL_MS);
    }
    throw std::runtime_error("Startup timed out or unpacked code did not match; no runtime edits applied");
}

static void* allocate_remote(HANDLE process, const void* data, SIZE_T length) {
    void* address = VirtualAllocEx(process, nullptr, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    win_require(address != nullptr, "Cannot allocate startup data");
    SIZE_T written = 0;
    win_require(WriteProcessMemory(process, address, data, length, &written) && written == length,
                "Cannot send startup data");
    return address;
}

static uintptr_t inject_library(Session& session, const std::wstring& dll_path) {
    const HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    const FARPROC load_library = GetProcAddress(kernel, "LoadLibraryW");
    win_require(load_library != nullptr, "Cannot resolve LoadLibraryW");
    HMODULE owner = nullptr;
    win_require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                  reinterpret_cast<LPCWSTR>(load_library), &owner), "Cannot resolve loader module");
    const auto remote_owner = find_module(session.pid, module_path(owner));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(owner);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(owner) + dos->e_lfanew);
    require(remote_owner.modBaseSize == nt->OptionalHeader.SizeOfImage, "Loader module sizes differ");
    const uintptr_t offset = reinterpret_cast<uintptr_t>(load_library) - reinterpret_cast<uintptr_t>(owner);
    require(offset < remote_owner.modBaseSize, "Loader export is outside its module");
    const auto entry = reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_owner.modBaseAddr + offset);
    void* argument = allocate_remote(session.process, dll_path.c_str(), (dll_path.size() + 1) * sizeof(wchar_t));
    const Handle thread(CreateRemoteThread(session.process, nullptr, 0, entry, argument, 0, nullptr));
    win_require(thread.value != nullptr, "Cannot load companion DLL in the new process");
    require(WaitForSingleObject(thread.value, WORKER_TIMEOUT_MS) == WAIT_OBJECT_0, "Companion DLL loading timed out");
    session.check_alive();
    const auto loaded = find_module(session.pid, dll_path);
    win_require(VirtualFreeEx(session.process, argument, 0, MEM_RELEASE), "Cannot release DLL-path buffer");
    return reinterpret_cast<uintptr_t>(loaded.modBaseAddr);
}

struct FrozenThread {
    DWORD id;
    Handle handle;
    FrozenThread(DWORD thread_id, HANDLE thread) : id(thread_id), handle(thread) {}
};

class FrozenThreads {
    std::vector<FrozenThread> threads;
public:
    bool freeze(DWORD pid, DWORD worker, uintptr_t base) {
        for (DWORD pass = 0; pass < SNAPSHOT_ATTEMPTS; ++pass) {
            const SIZE_T previous_count = threads.size();
            const auto list = snapshot(TH32CS_SNAPTHREAD, 0);
            THREADENTRY32 entry = {};
            entry.dwSize = sizeof(entry);
            win_require(Thread32First(list.value, &entry), "Cannot enumerate application threads");
            do {
                if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == worker) continue;
                if (std::any_of(threads.begin(), threads.end(), [&](const auto& t) { return t.id == entry.th32ThreadID; }))
                    continue;
                const HANDLE handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT
                                                 | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                                 FALSE, entry.th32ThreadID);
                if (!handle && GetLastError() == ERROR_INVALID_PARAMETER) continue;
                win_require(handle != nullptr, "Cannot open a newly created application thread");
                threads.emplace_back(entry.th32ThreadID, handle);
                const DWORD owner = GetProcessIdOfThread(handle);
                win_require(owner != 0, "Cannot verify thread ownership");
                if (owner != pid) {
                    threads.pop_back();
                    continue;
                }
                if (SuspendThread(handle) == static_cast<DWORD>(-1)) {
                    if (WaitForSingleObject(handle, 0) == WAIT_OBJECT_0) {
                        threads.pop_back();
                        continue;
                    }
                    win_require(false, "Cannot pause an application thread");
                }
                CONTEXT context = {};
                context.ContextFlags = CONTEXT_CONTROL;
                win_require(GetThreadContext(handle, &context), "Cannot inspect a paused instruction pointer");
                for (const auto& spec : PATCHES) {
                    if (context.Rip >= base + spec.rva && context.Rip < base + spec.rva + spec.span) {
                        thaw();
                        return false;
                    }
                }
            } while (Thread32Next(list.value, &entry));
            require(GetLastError() == ERROR_NO_MORE_FILES, "Thread enumeration was incomplete");
            if (threads.size() == previous_count) return true;
        }
        throw std::runtime_error("Application thread list did not stabilize");
    }
    void thaw() {
        for (auto& thread : threads)
            win_require(ResumeThread(thread.handle.value) != static_cast<DWORD>(-1), "Cannot resume an application thread");
        threads.clear();
    }
};

static SharedState wait_for_state(Session& session, HANDLE worker, void* remote, LONG desired, DWORD timeout) {
    const ULONGLONG deadline = GetTickCount64() + timeout;
    while (GetTickCount64() < deadline) {
        session.check_alive();
        SharedState state = {};
        SIZE_T read = 0;
        win_require(ReadProcessMemory(session.process, remote, &state, sizeof(state), &read) && read == sizeof(state),
                    "Cannot read companion status");
        if (state.state == STATE_DONE || state.state == desired) return state;
        require(WaitForSingleObject(worker, 0) == WAIT_TIMEOUT, "Companion worker exited without completing");
        Sleep(POLL_MS);
    }
    throw std::runtime_error("Companion worker timed out");
}

static void* apply_runtime(Session& session, uintptr_t base, uintptr_t dll_base, uintptr_t export_offset) {
    const SharedState initial = {COMMAND_WAIT, STATE_STARTING, ERROR_SUCCESS, 0};
    void* remote = allocate_remote(session.process, &initial, sizeof(initial));
    DWORD worker_id = 0;
    const auto entry = reinterpret_cast<LPTHREAD_START_ROUTINE>(dll_base + export_offset);
    const Handle worker(CreateRemoteThread(session.process, nullptr, 0, entry, remote, 0, &worker_id));
    win_require(worker.value != nullptr, "Cannot start companion worker");
    const auto ready = wait_for_state(session, worker.value, remote, STATE_READY, WORKER_TIMEOUT_MS);
    require(ready.state == STATE_READY, "Companion worker did not enter the ready state");

    FrozenThreads frozen;
    bool paused = false;
    for (DWORD attempt = 0; attempt < FREEZE_ATTEMPTS; ++attempt) {
        if (frozen.freeze(session.pid, worker_id, base)) {
            paused = true;
            break;
        }
        Sleep(POLL_MS);
    }
    require(paused, "Application was executing code selected for replacement; no runtime edits applied");
    require(guards_match(session.process, base), "Code changed before patching; refusing runtime edits");
    const LONG command = COMMAND_APPLY;
    SIZE_T written = 0;
    win_require(WriteProcessMemory(session.process, remote, &command, sizeof(command), &written) && written == sizeof(command),
                "Cannot authorize companion edits");
    const auto done = wait_for_state(session, worker.value, remote, STATE_DONE, PATCH_TIMEOUT_MS);
    require(done.state == STATE_DONE && done.status == ERROR_SUCCESS && done.applied == PATCH_COUNT,
            ("Companion patch failed (status " + std::to_string(done.status) + "); terminating only the new process").c_str());
    frozen.thaw();
    require(WaitForSingleObject(worker.value, PATCH_TIMEOUT_MS) == WAIT_OBJECT_0, "Companion worker did not exit");
    session.check_alive();
#ifdef SYNTHV_TRACE
    return remote;
#else
    win_require(VirtualFreeEx(session.process, remote, 0, MEM_RELEASE), "Cannot release companion status buffer");
    return nullptr;
#endif
}

#ifdef SYNTHV_TRACE
static bool read_image(HANDLE process, uintptr_t base, DWORD image_size, uintptr_t rva, void* output, SIZE_T size) {
    if (!rva || rva >= image_size || size > image_size - rva) return false;
    SIZE_T read = 0;
    return ReadProcessMemory(process, reinterpret_cast<void*>(base + rva), output, size, &read) && read == size;
}

static std::string exception_type(HANDLE process, uintptr_t base, DWORD image_size, uintptr_t throw_rva) {
    DWORD info[4] = {};
    DWORD types[2] = {};
    DWORD first[2] = {};
    if (!read_image(process, base, image_size, throw_rva, info, sizeof(info))
        || !read_image(process, base, image_size, info[3], types, sizeof(types))
        || !types[0] || types[0] > TRACE_CAPACITY
        || !read_image(process, base, image_size, types[1], first, sizeof(first)))
        return "(unavailable)";
    char name[TYPE_NAME_CAPACITY] = {};
    if (!read_image(process, base, image_size, static_cast<uintptr_t>(first[1]) + TYPE_DESCRIPTOR_NAME_OFFSET,
                    name, sizeof(name)) || std::strncmp(name, ".?A", 3) != 0)
        return "(unavailable)";
    name[sizeof(name) - 1] = '\0';
    for (const char* value = name; *value; ++value)
        if (*value < ' ' || *value > '~') return "(unavailable)";
    return name;
}

static void monitor_trace(Session& session, void* remote, uintptr_t base, const std::wstring& target) {
    const DWORD image_size = find_module(session.pid, target).modBaseSize;
    bool printed[TRACE_CAPACITY] = {};
    bool limit_reported = false;
    std::puts("Diagnostic capture is active. Reproduce the offline-rendering error, then copy the console output.\n"
              "Only C++ exception types, thread IDs and application stack RVAs are shown. No log files are written.\n"
              "First-chance exceptions can be handled normally; their presence alone does not identify a failure.");
    std::fflush(stdout);
    while (WaitForSingleObject(session.process, POLL_MS) == WAIT_TIMEOUT) {
        SharedState state = {};
        SIZE_T read = 0;
        if (!ReadProcessMemory(session.process, remote, &state, sizeof(state), &read) || read != sizeof(state)) {
            if (WaitForSingleObject(session.process, 0) == WAIT_OBJECT_0) break;
            throw std::runtime_error("Cannot read diagnostic events; the running app has not been terminated");
        }
        const LONG count = std::min(state.event_count, TRACE_CAPACITY);
        for (LONG i = 0; i < count; ++i) {
            const auto& event = state.events[i];
            if (printed[i] || !event.ready) continue;
            printed[i] = true;
            const auto type = exception_type(session.process, base, image_size, event.throw_info_rva);
            std::printf("C++ event %ld: thread=%lu type=%s throw-info RVA=0x%llx\n",
                        i + 1, event.thread_id, type.c_str(), static_cast<unsigned long long>(event.throw_info_rva));
            std::printf("  application stack:");
            for (DWORD frame = 0; frame < std::min<DWORD>(event.frame_count, TRACE_FRAME_LIMIT); ++frame)
                std::printf(" 0x%llx", static_cast<unsigned long long>(event.frames[frame]));
            if (!event.frame_count) std::printf(" (unavailable)");
            std::putchar('\n');
        }
        if (count == TRACE_CAPACITY && !limit_reported) {
            std::puts("Capture capacity reached; later exceptions will not be recorded.");
            limit_reported = true;
        }
        std::fflush(stdout);
    }
    std::puts("Application exited. Copy the relevant output before pressing Enter to close.");
    std::getchar();
}
#endif

int wmain() {
    std::puts("Experimental Synthesizer V runtime patch\n"
              "Offline rendering and expired voicebanks are NOT established. This is not the complete RFC.\n"
              "The installed EXE is not edited. The app may perform its normal settings/network activity.\n"
              "Close this window to cancel, or type APPLY and press Enter to launch.");
#ifdef SYNTHV_TRACE
    std::puts("This diagnostic build adds exception observation, NOT an offline-rendering fix.\n"
              "Do not interact with the new application until diagnostic capture is active.");
#endif
    char confirmation[16] = {};
    if (!std::fgets(confirmation, sizeof(confirmation), stdin) || std::strcmp(confirmation, "APPLY\n") != 0) return 0;
    try {
        const Handle mutex(CreateMutexW(nullptr, FALSE, LAUNCHER_MUTEX));
        const DWORD mutex_status = GetLastError();
        win_require(mutex.value != nullptr, "Cannot create launcher lock");
        require(mutex_status != ERROR_ALREADY_EXISTS, "Another runtime launcher is already active");
        const std::wstring self = module_path(nullptr);
        const auto separator = self.find_last_of(L"\\/");
        require(separator != std::wstring::npos, "Cannot determine launcher directory");
        const std::wstring directory = self.substr(0, separator);
        const std::wstring target = directory + L"\\" + TARGET_NAME;
        const std::wstring dll_path = directory + L"\\" + DLL_NAME;
        require_no_existing_app();
        const Handle target_file(CreateFileW(target.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
        win_require(target_file.value != INVALID_HANDLE_VALUE, "Cannot lock the original executable for reading");
        require(fingerprint(target_file.value) == ORIGINAL_SHA256, "Unknown or modified executable; refusing to launch");
        const Handle dll_file(CreateFileW(dll_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
        win_require(dll_file.value != INVALID_HANDLE_VALUE, "Cannot lock the companion DLL for reading");
        require(fingerprint(dll_file.value) == DLL_SHA256, "Companion DLL does not match this launcher; rebuild both together");
        const HMODULE local_dll = LoadLibraryExW(dll_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        win_require(local_dll != nullptr, "Cannot inspect the companion DLL export");
        const FARPROC exported = GetProcAddress(local_dll, PATCH_EXPORT);
        const uintptr_t export_offset = reinterpret_cast<uintptr_t>(exported) - reinterpret_cast<uintptr_t>(local_dll);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(local_dll);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(local_dll) + dos->e_lfanew);
        const bool valid_export = exported && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64
                                  && export_offset < nt->OptionalHeader.SizeOfImage;
        FreeLibrary(local_dll);
        require(valid_export, "Companion DLL has no valid x64 patch entry point");

        Session session;
        session.start(target, directory);
        std::puts("Waiting for unpacked code and an idle application window...");
        const uintptr_t base = wait_for_unpack(session, target);
        const uintptr_t dll_base = inject_library(session, dll_path);
        void* trace = apply_runtime(session, base, dll_base, export_offset);
        session.release();
        std::puts("Six runtime edits installed; byte verification does not establish functional correctness.\n"
                  "For an unmodified session, close the app and launch synthv-studio.exe directly.");
#ifdef SYNTHV_TRACE
        monitor_trace(session, trace, base, target);
#endif
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Error: %s\nThe installed executable was not changed.\nPress Enter to close.\n", error.what());
        std::getchar();
        return 1;
    }
}
