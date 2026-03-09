@echo off
title AiDA Bot Launcher Build
echo.
echo  ╔═══════════════════════════════════════╗
echo  ║   AiDA License Bot — Launcher Build   ║
echo  ╚═══════════════════════════════════════╝
echo.
echo Compiling BotLauncher.exe...

set CSC_PATH="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

%CSC_PATH% /target:winexe /out:BotLauncher.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll /win32icon:bot.ico BotLauncher.cs 2>nul
if %errorlevel% neq 0 (
    echo [!] Icon not found, building without custom icon...
    %CSC_PATH% /target:winexe /out:BotLauncher.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll BotLauncher.cs
)

if %errorlevel% equ 0 (
    echo.
    echo  ========================================
    echo   SUCCESS! BotLauncher.exe created.
    echo  ========================================
    echo.
    echo  Features:
    echo    - Starts bot.js on launch
    echo    - Auto-restarts on crash (5s delay)
    echo    - Minimizes to system tray
    echo    - Right-click tray: Restart / Toggle Startup / Exit
    echo    - Single-instance lock (prevents duplicates)
    echo    - Closing window = minimize (tray Exit to quit)
    echo.
) else (
    echo.
    echo  Compilation FAILED.
)
pause