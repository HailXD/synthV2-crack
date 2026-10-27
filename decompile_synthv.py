import os
from pathlib import Path
import subprocess


APP_DIR = Path(r"C:\Program Files\Synthesizer V Studio 2 Pro")
HEADLESS = Path.home() / "scoop/apps/ghidra/current/support/analyzeHeadless.bat"
PROJECT_DIR = APP_DIR / "analysis"
PROJECT_NAME = "synthv-license"
INPUT_NAME = "text.bin"
SCRIPT_DIR = APP_DIR / ".analysis"
SCRIPT_NAME = "TraceLicense.java"
LOG_CONFIG = PROJECT_DIR / "console.xml"


def main():
    environment = os.environ.copy()
    environment["JDK_JAVA_OPTIONS"] = f'-Dlog4j.configurationFile="{LOG_CONFIG.as_posix()}"'
    subprocess.run(
        [str(HEADLESS), str(PROJECT_DIR), PROJECT_NAME, "-process", INPUT_NAME,
         "-readOnly", "-noanalysis", "-scriptPath", str(SCRIPT_DIR),
         "-postScript", SCRIPT_NAME, "-log", "NUL", "-scriptlog", "NUL"],
        cwd=APP_DIR,
        env=environment,
        check=True,
    )


if __name__ == "__main__":
    main()
