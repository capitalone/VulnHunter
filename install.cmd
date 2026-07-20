@echo off
setlocal EnableDelayedExpansion

rem USERPROFILE guard: destinations (and the rmdir below) derive from
rem USERPROFILE. An unset USERPROFILE would turn deletes into operations on
rem a bad root path -- refuse cleanly.
if "%USERPROFILE%"=="" (
    echo error: USERPROFILE unset -- refusing to run install.cmd 1>&2
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "SKILLS_PARENT=%USERPROFILE%\.claude\skills"

if not exist "%SKILLS_PARENT%" (
    echo Creating directory %SKILLS_PARENT%
    mkdir "%SKILLS_PARENT%"
)

set "PYEXE="
call :find_python
if "%PYEXE%"=="" (
    echo error: python 3.11+ not found ^(needed for vulnhunter-fix's bundled venv^). 1>&2
    echo install Python 3.11+ from https://www.python.org/downloads/ and re-run install.cmd. 1>&2
    exit /b 1
)

set "installed_any=0"
for %%S in (vulnhunt vulnhunt-fix-verify vulnhunter-fix) do (
    call :install_one "%%S"
    if errorlevel 1 exit /b 1
)

echo.
if "%installed_any%"=="1" (
    echo To update after pulling changes: re-run install.cmd
    echo To uninstall: "%SCRIPT_DIR%\uninstall.cmd"
) else (
    echo No skills were installed.
)

endlocal
exit /b 0

:install_one
setlocal
set "name=%~1"
set "src=%SCRIPT_DIR%\%name%"
set "dst=%SKILLS_PARENT%\%name%"

if not exist "%src%\SKILL.md" (
    if "%name%"=="vulnhunt" (
        echo Error: SKILL.md not found at %src% 1>&2
        echo Make sure you are running this script from the repository root. 1>&2
        endlocal & exit /b 1
    ) else (
        echo Skipping %name% -- %src%\SKILL.md not present on this branch.
        endlocal & exit /b 0
    )
)

rem Handle an existing destination (junction/symlink or plain directory).
if exist "%dst%\" (
    echo Removing old copy of %name%...
    rmdir /s /q "%dst%"
)

rem Copy files (not a symlink/junction -- links break find/glob in subagents).
robocopy "%src%" "%dst%" /E /NFL /NDL /NJH /NJS >nul
if errorlevel 8 (
    echo error: failed to copy %src% to %dst% 1>&2
    endlocal & exit /b 1
)

rem Record the source commit so a skill's staleness check (e.g.
rem vulnhunter-fix SKILL.md Step 0b) can compare the installed copy against
rem upstream main. Best-effort: skipped outside a git checkout.
git -C "%SCRIPT_DIR%" rev-parse HEAD > "%dst%\.installed-from" 2>nul
echo Installed %name% (copied to %dst%)

rem vulnhunter-fix ships a Python package whose runtime deps (jsonschema,
rem graphifyy) must live in a bundled venv that scripts\_skill_bootstrap.py
rem loads. The other skills are prompt-only and need no venv.
if "%name%"=="vulnhunter-fix" (
    call :build_vulnfix_venv "%dst%"
    if errorlevel 1 (
        endlocal & exit /b 1
    )
)

endlocal & set "installed_any=1" & exit /b 0

:build_vulnfix_venv
setlocal
set "skill_dir=%~1"
set "venv=%skill_dir%\.venv"

if exist "%venv%\" (
    rmdir /s /q "%venv%"
)
echo   creating bundled venv with %PYEXE%
rem Note: interpreter/launcher failures can exit with large negative codes,
rem which "if errorlevel N" misreads as success. Check !ERRORLEVEL! for
rem exact equality to 0 instead.
call %PYEXE% -m venv "%venv%"
if not !ERRORLEVEL!==0 (
    echo error: failed to create venv at %venv% 1>&2
    endlocal & exit /b 1
)

"%venv%\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check --upgrade pip
echo   installing runtime deps into venv: jsonschema^>=4.18 graphifyy^>=0.8.14,^<0.9.0
"%venv%\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check "jsonschema>=4.18" "graphifyy>=0.8.14,<0.9.0"
if not !ERRORLEVEL!==0 (
    echo error: failed to install bundled deps into %venv% 1>&2
    endlocal & exit /b 1
)

rem Smoke test: the bootstrap must resolve both deps.
call %PYEXE% -c "import sys; sys.path.insert(0, r'%skill_dir%\scripts'); import _skill_bootstrap; import jsonschema, graphify" >nul 2>&1
if not !ERRORLEVEL!==0 (
    echo error: bootstrap smoke test failed -- venv built but jsonschema/graphify not importable. 1>&2
    echo        check %venv%\Lib\site-packages\ 1>&2
    endlocal & exit /b 1
)
echo   bundled venv ready: %venv%
endlocal & exit /b 0

:find_python
rem Prefer the py launcher pinned to 3.11 (graphifyy ships per-minor wheels
rem and 3.11 is the reference minor); otherwise accept any interpreter that
rem satisfies pyproject's requires-python (>=3.11).
rem Note: some launcher/interpreter failures exit with large negative codes
rem (e.g. "py -3.11" when 3.11 isn't installed), which "if errorlevel N"
rem misreads as success since it compares signed integers against N. Check
rem !ERRORLEVEL! for exact equality to 0 instead.
where py >nul 2>nul
if !ERRORLEVEL!==0 (
    py -3.11 -c "import sys" >nul 2>nul
    if !ERRORLEVEL!==0 (
        set "PYEXE=py -3.11"
        exit /b 0
    )
)
for %%C in (python3.13 python3.12 python3.11 python) do (
    where %%C >nul 2>nul
    if !ERRORLEVEL!==0 (
        %%C -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)" >nul 2>nul
        if !ERRORLEVEL!==0 (
            set "PYEXE=%%C"
            exit /b 0
        )
    )
)
exit /b 0
