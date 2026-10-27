import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


APP_DIR = Path(r"C:\Program Files\Synthesizer V Studio 2 Pro")
COMPILER = (
    Path.home()
    / "scoop/apps/mingw-mstorsjo-llvm-ucrt/current/bin/x86_64-w64-mingw32-clang++.exe"
)
BUILD_DIAGNOSTIC = True
DLL_NAME = "synthv-trace.dll" if BUILD_DIAGNOSTIC else "synthv-runtime.dll"
LAUNCHER_NAME = "synthv-trace.exe" if BUILD_DIAGNOSTIC else "synthv-launcher.exe"
MODE_FLAGS = ("-DSYNTHV_TRACE",) if BUILD_DIAGNOSTIC else ()
COMMON_FLAGS = ("-std=c++17", "-O2", "-static", "-Wl,--dynamicbase,--nxcompat,--no-insert-timestamp,-s", *MODE_FLAGS)


def build():
    if not COMPILER.is_file():
        raise SystemExit("Install the compiler with: scoop install mingw-mstorsjo-llvm-ucrt")
    with tempfile.TemporaryDirectory(prefix=".synthv-build-", dir=APP_DIR) as temporary:
        directory = Path(temporary)
        dll = directory / DLL_NAME
        launcher = directory / LAUNCHER_NAME
        subprocess.run(
            [str(COMPILER), *COMMON_FLAGS, "-shared", "-fno-exceptions", "-fno-rtti",
             "runtime_hook.cpp", "-o", str(dll)],
            cwd=APP_DIR,
            check=True,
        )
        dll_hash = hashlib.sha256(dll.read_bytes()).hexdigest()
        subprocess.run(
            [str(COMPILER), *COMMON_FLAGS, "-municode", f'-DCOMPANION_SHA256="{dll_hash}"',
             "runtime_launcher.cpp", "-lbcrypt", "-o", str(launcher)],
            cwd=APP_DIR,
            check=True,
        )
        os.replace(dll, APP_DIR / DLL_NAME)
        os.replace(launcher, APP_DIR / LAUNCHER_NAME)
    print(f"Built: {APP_DIR / LAUNCHER_NAME}")
    print(f"Companion: {APP_DIR / DLL_NAME}")
    print("No application launch or functional tests performed.")
    if BUILD_DIAGNOSTIC:
        print("Diagnostic build only; no new offline-rendering bypass. Existing launcher binaries were not replaced.")
    else:
        print("Experimental partial patch only.")


if __name__ == "__main__":
    build()
