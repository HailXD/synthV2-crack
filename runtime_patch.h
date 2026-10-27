#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstddef>
#include <cstdint>

inline constexpr wchar_t TARGET_NAME[] = L"synthv-studio.exe";
#ifdef SYNTHV_TRACE
inline constexpr wchar_t DLL_NAME[] = L"synthv-trace.dll";
inline constexpr DWORD CPP_EXCEPTION_CODE = 0xE06D7363;
inline constexpr LONG TRACE_CAPACITY = 64;
inline constexpr USHORT TRACE_FRAME_LIMIT = 48;
inline constexpr SIZE_T TYPE_NAME_CAPACITY = 128;
inline constexpr DWORD TYPE_DESCRIPTOR_NAME_OFFSET = 16;
#else
inline constexpr wchar_t DLL_NAME[] = L"synthv-runtime.dll";
#endif
inline constexpr char ORIGINAL_SHA256[] = "7d81044df4827d21a1f232d2eb42d37d5ac87648abfb406a34f027e4e74ca35b";
inline constexpr char PATCH_EXPORT[] = "ApplyRuntimePatches";
inline constexpr char COUNTDOWN_TEXT[] = "Trial expires in \xe2\x88\x9e days";
inline constexpr uintptr_t STRING_CONSTRUCTOR_RVA = 0x7FCED0;
inline constexpr SIZE_T GUARD_SIZE = 32;
inline constexpr DWORD STARTUP_TIMEOUT_MS = 60000;
inline constexpr DWORD WORKER_TIMEOUT_MS = 30000;
inline constexpr DWORD PATCH_TIMEOUT_MS = 10000;
inline constexpr DWORD POLL_MS = 50;
inline constexpr DWORD STABLE_SAMPLES = 5;
inline constexpr DWORD FREEZE_ATTEMPTS = 20;
inline constexpr DWORD SNAPSHOT_ATTEMPTS = 8;
inline constexpr LONG STATE_STARTING = 0;
inline constexpr LONG STATE_READY = 1;
inline constexpr LONG STATE_DONE = 2;
inline constexpr LONG COMMAND_WAIT = 0;
inline constexpr LONG COMMAND_APPLY = 1;

struct PatchSpec {
    const char* name;
    uintptr_t rva;
    const char* before;
    const char* after;
    SIZE_T span;
};

inline constexpr PatchSpec PATCHES[] = {
    {"note-cap getter", 0xAB0AF0,
     "40534881ec40010000488bd9e80f30c5ff488b5308488bc8e823bc0400488bd0",
     "b8ffffffffc3909090", 9},
    {"editor-expiry getter", 0xAFD0E0,
     "40534881ec60010000488b05d089da004833c44889842450010000e85050ffff",
     "31c0c3909090909090", 9},
    {"editor-type getter", 0xAFD180,
     "488bc4488958104889681856574154415641574881ecd00000000f2970c80f29",
     "b802000000c390", 7},
    {"trial export-list branch", 0xB513AB,
     "0f845c010000488d4df0e83625bbff488d4da0e82d25bbff488d4d88e81450bb",
     "909090909090", 6},
    {"trial render-warning branch", 0xD528D6,
     "744e488d4d80e8cf4d9cff90488b5c24284885db742b8bc7f00fc1430883f801",
     "9090", 2},
    {"English infinity countdown hook", 0xDAD190,
     "488bc4488958084889701855574156488da828ffffff4881ecc00100000f2970",
     nullptr, 15},
    {"UTF-8 string-constructor guard", STRING_CONSTRUCTOR_RVA,
     "48895c2410488974241848897c242041564883ec20498d58044c8bf14883e3fc",
     "", 0}
};

inline constexpr SIZE_T SPEC_COUNT = sizeof(PATCHES) / sizeof(PATCHES[0]);
inline constexpr SIZE_T PATCH_COUNT = SPEC_COUNT - 1;

#ifdef SYNTHV_TRACE
struct ExceptionTrace {
    LONG ready;
    DWORD thread_id;
    uintptr_t throw_info_rva;
    DWORD frame_count;
    uintptr_t frames[TRACE_FRAME_LIMIT];
};
#endif

struct SharedState {
    LONG command;
    LONG state;
    DWORD status;
    DWORD applied;
#ifdef SYNTHV_TRACE
    LONG tracing;
    LONG event_count;
    ExceptionTrace events[TRACE_CAPACITY];
#endif
};

inline BYTE hex_digit(char value) {
    return static_cast<BYTE>(value <= '9' ? value - '0' : value - 'a' + 10);
}

inline void decode_bytes(const char* hex, BYTE* bytes, SIZE_T length) {
    for (SIZE_T i = 0; i < length; ++i)
        bytes[i] = static_cast<BYTE>((hex_digit(hex[i * 2]) << 4) | hex_digit(hex[i * 2 + 1]));
}

inline bool equal_bytes(const BYTE* left, const BYTE* right, SIZE_T length) {
    for (SIZE_T i = 0; i < length; ++i)
        if (left[i] != right[i]) return false;
    return true;
}
