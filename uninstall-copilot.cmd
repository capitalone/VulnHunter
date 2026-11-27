@echo off
setlocal EnableDelayedExpansion

rem USERPROFILE guard: dst (and its rmdir /s /q) derive from USERPROFILE. An
rem unset USERPROFILE would turn deletes into operations on a bad root path
rem -- refuse cleanly. The recursive remove already takes the bundled .venv
rem with it.
if "%USERPROFILE%"=="" (
    echo error: USERPROFILE unset -- refusing to run uninstall-copilot.cmd 1>&2
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "SKILLS_PARENT=%USERPROFILE%\.copilot\skills"

rem Skill names to remove (must match the names install-copilot.cmd writes).
set "removed_any=0"
for %%S in (vulnhunt vulnhunt-fix-verify vulnhunter-fix) do (
    set "dst=%SKILLS_PARENT%\%%S"
    if exist "!dst!\" (
        rmdir /s /q "!dst!"
        echo Removed !dst!
        set "removed_any=1"
    ) else (
        echo %%S is not installed ^(no entry at !dst!^)
    )
)

rem Best-effort: revert the agent-terminal setting install-copilot.cmd wrote,
rem but only if it still looks unchanged since install (see the script for
rem the exact condition). Runs regardless of removed_any, since a user can
rem re-run uninstall after skills are already gone just to clean this up.
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%\vulnhunt-copilot\scripts\windows\remove-terminal-profile.ps1"

echo.
if "%removed_any%"=="1" (
    echo Uninstalled VulnHunter Copilot Agent Skills.
) else (
    echo Nothing to uninstall.
)

endlocal
exit /b 0
