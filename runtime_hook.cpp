#include "runtime_patch.h"

static BYTE* IMAGE_BASE = nullptr;
static LONG APPLIED = 0;

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
    InterlockedExchange(&shared->state, STATE_DONE);
    return status;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH)
        IMAGE_BASE = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
    return TRUE;
}
