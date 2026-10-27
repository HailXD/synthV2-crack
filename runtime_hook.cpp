#include "runtime_patch.h"

static BYTE* IMAGE_BASE = nullptr;
static LONG APPLIED = 0;

#ifdef SYNTHV_TRACE
static SharedState* TRACE_STATE = nullptr;
static LONG CAPTURE_BUSY = 0;
static DWORD IMAGE_SIZE = 0;

static bool image_address(uintptr_t address) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(IMAGE_BASE);
    return address >= base && address - base < IMAGE_SIZE;
}

static LONG CALLBACK observe_exception(EXCEPTION_POINTERS* exception) {
    if (!TRACE_STATE || !InterlockedCompareExchange(&TRACE_STATE->tracing, 0, 0)
        || exception->ExceptionRecord->ExceptionCode != CPP_EXCEPTION_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedCompareExchange(&CAPTURE_BUSY, 1, 0)) return EXCEPTION_CONTINUE_SEARCH;
    if (TRACE_STATE->event_count < TRACE_CAPACITY) {
        const LONG index = InterlockedIncrement(&TRACE_STATE->event_count) - 1;
        auto& event = TRACE_STATE->events[index];
        event.thread_id = GetCurrentThreadId();
        const auto* record = exception->ExceptionRecord;
        if (record->NumberParameters >= 4 && image_address(record->ExceptionInformation[2]))
            event.throw_info_rva = record->ExceptionInformation[2] - reinterpret_cast<uintptr_t>(IMAGE_BASE);
        void* frames[TRACE_FRAME_LIMIT] = {};
        const USHORT count = CaptureStackBackTrace(0, TRACE_FRAME_LIMIT, frames, nullptr);
        for (USHORT i = 0; i < count; ++i) {
            const uintptr_t address = reinterpret_cast<uintptr_t>(frames[i]);
            if (image_address(address))
                event.frames[event.frame_count++] = address - reinterpret_cast<uintptr_t>(IMAGE_BASE);
        }
        InterlockedExchange(&event.ready, 1);
    }
    InterlockedExchange(&CAPTURE_BUSY, 0);
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

using StringConstructor = void* (*)(void*, const char*, SIZE_T);

static void* infinity_countdown(void*, void* result) {
    const auto construct = reinterpret_cast<StringConstructor>(IMAGE_BASE + STRING_CONSTRUCTOR_RVA);
    return construct(result, COUNTDOWN_TEXT, sizeof(COUNTDOWN_TEXT) - 1);
}

static DWORD apply_patches(DWORD* applied) {
    BYTE replacements[SPEC_COUNT][GUARD_SIZE] = {};
    DWORD protection[SPEC_COUNT] = {};
    SIZE_T protected_count = 0;
    DWORD status = ERROR_SUCCESS;
    const HANDLE process = GetCurrentProcess();

    for (SIZE_T i = 0; i < SPEC_COUNT; ++i) {
        const auto& spec = PATCHES[i];
        BYTE expected[GUARD_SIZE];
        BYTE actual[GUARD_SIZE];
        SIZE_T read = 0;
        decode_bytes(spec.before, expected, GUARD_SIZE);
        if (!ReadProcessMemory(process, IMAGE_BASE + spec.rva, actual, GUARD_SIZE, &read)
            || read != GUARD_SIZE || !equal_bytes(actual, expected, GUARD_SIZE))
            return ERROR_REVISION_MISMATCH;
        if (!spec.span) continue;
        if (spec.after) {
            decode_bytes(spec.after, replacements[i], spec.span);
        } else {
            BYTE* code = replacements[i];
            code[0] = 0xFF;
            code[1] = 0x25;
            const uintptr_t hook = reinterpret_cast<uintptr_t>(&infinity_countdown);
            for (SIZE_T byte = 0; byte < sizeof(hook); ++byte)
                code[6 + byte] = static_cast<BYTE>(hook >> (byte * 8));
            code[14] = 0x90;
        }
    }

    for (SIZE_T i = 0; i < PATCH_COUNT; ++i) {
        const auto& spec = PATCHES[i];
        if (!VirtualProtect(IMAGE_BASE + spec.rva, spec.span, PAGE_EXECUTE_READWRITE, &protection[i])) {
            status = GetLastError();
            break;
        }
        ++protected_count;
    }

    if (status == ERROR_SUCCESS) {
        for (SIZE_T i = 0; i < PATCH_COUNT; ++i) {
            const auto& spec = PATCHES[i];
            SIZE_T written = 0;
            SIZE_T read = 0;
            BYTE actual[GUARD_SIZE];
            if (!WriteProcessMemory(process, IMAGE_BASE + spec.rva, replacements[i], spec.span, &written)
                || written != spec.span
                || !FlushInstructionCache(process, IMAGE_BASE + spec.rva, spec.span)
                || !ReadProcessMemory(process, IMAGE_BASE + spec.rva, actual, spec.span, &read)
                || read != spec.span || !equal_bytes(actual, replacements[i], spec.span)) {
                status = ERROR_WRITE_FAULT;
                break;
            }
            ++*applied;
        }
    }

    while (protected_count) {
        const SIZE_T i = --protected_count;
        DWORD ignored = 0;
        if (!VirtualProtect(IMAGE_BASE + PATCHES[i].rva, PATCHES[i].span, protection[i], &ignored))
            status = ERROR_ACCESS_DENIED;
    }
    return status;
}

extern "C" __declspec(dllexport) DWORD WINAPI ApplyRuntimePatches(void* parameter) {
    auto* shared = static_cast<SharedState*>(parameter);
    if (!shared || !IMAGE_BASE) return ERROR_INVALID_PARAMETER;
    if (InterlockedCompareExchange(&APPLIED, 1, 0) != 0) {
        shared->status = ERROR_ALREADY_EXISTS;
        InterlockedExchange(&shared->state, STATE_DONE);
        return shared->status;
    }
#ifdef SYNTHV_TRACE
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(IMAGE_BASE);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(IMAGE_BASE + dos->e_lfanew);
    IMAGE_SIZE = nt->OptionalHeader.SizeOfImage;
    TRACE_STATE = shared;
    if (!AddVectoredExceptionHandler(0, observe_exception)) {
        shared->status = ERROR_NOT_SUPPORTED;
        InterlockedExchange(&shared->state, STATE_DONE);
        return shared->status;
    }
#endif
    InterlockedExchange(&shared->state, STATE_READY);
    const ULONGLONG deadline = GetTickCount64() + WORKER_TIMEOUT_MS;
    while (InterlockedCompareExchange(&shared->command, COMMAND_WAIT, COMMAND_WAIT) != COMMAND_APPLY) {
        if (GetTickCount64() >= deadline) {
            shared->status = ERROR_TIMEOUT;
            InterlockedExchange(&shared->state, STATE_DONE);
            return ERROR_TIMEOUT;
        }
        Sleep(POLL_MS);
    }
    shared->status = apply_patches(&shared->applied);
    const DWORD status = shared->status;
#ifdef SYNTHV_TRACE
    if (status == ERROR_SUCCESS) InterlockedExchange(&shared->tracing, 1);
#endif
    InterlockedExchange(&shared->state, STATE_DONE);
    return status;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH)
        IMAGE_BASE = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
    return TRUE;
}
