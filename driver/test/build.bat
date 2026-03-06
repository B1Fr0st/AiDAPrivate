@echo off
setlocal

set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo ERROR: Could not find vcvars64.bat
    echo Expected: %VCVARS%
    exit /b 1
)

call "%VCVARS%" >nul 2>&1

echo Assembling syscall.asm...
ml64 /c /nologo /Fo "%~dp0syscall.obj" "%~dp0..\syscall.asm"
if errorlevel 1 (
    echo ERROR: Failed to assemble syscall.asm
    exit /b 1
)

echo Compiling WhosWhoTest...
cl /std:c++17 /EHsc /O2 /nologo /W3 /I"%~dp0.." /Fe:"%~dp0WhosWhoTest.exe" "%~dp0WhosWhoTest.cpp" "%~dp0..\comm.cpp" "%~dp0syscall.obj" kernel32.lib user32.lib ntdll.lib advapi32.lib
if errorlevel 1 (
    echo ERROR: Failed to compile
    exit /b 1
)

echo.
echo Build successful: WhosWhoTest.exe
