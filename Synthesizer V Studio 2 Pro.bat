@echo off
setlocal
set "APP=synthv-studio.exe"
set "PATCHER=patch_voice_limit.py"
pushd "%~dp0" || exit /b 1
where python >nul 2>&1
if errorlevel 1 goto failed
if not exist "%APP%" goto failed
if not exist "%PATCHER%" goto failed
start "" "%APP%"
if errorlevel 1 goto failed
python -B "%PATCHER%"
if errorlevel 1 goto failed
popd
exit /b 0

:failed
echo Launch or patch failed. Check Python, the files above, and any displayed error.
echo If Synthesizer V opened, it may still be unpatched.
pause
popd
exit /b 1
