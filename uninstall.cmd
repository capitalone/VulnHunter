@echo off
setlocal EnableDelayedExpansion

rem USERPROFILE guard: dst (and its rmdir /s /q) derive from USERPROFILE. An
rem unset USERPROFILE would turn deletes into operations on a bad root path
rem -- refuse cleanly. The recursive remove already takes the bundled .venv
rem with it.
if "%USERPROFILE%"=="" (
    echo error: USERPROFILE unset -- refusing to run uninstall.cmd 1>&2
    exit /b 1
)

set "SKILLS_PARENT=%USERPROFILE%\.claude\skills"

rem Skill names to remove (must match the names install.cmd writes).
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

echo.
if "%removed_any%"=="1" (
    echo Uninstalled VulnHunter skills.
) else (
    echo Nothing to uninstall.
)

endlocal
exit /b 0
