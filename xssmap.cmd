@echo off
rem xssmap launcher (Windows cmd)
rem
rem Two things this must get right:
rem   1. %ERRORLEVEL% inside a parenthesised block is expanded when the block is
rem      parsed, not when it runs, so the naive form reports the status of the
rem      "where" probe instead of the scanner. Delayed expansion (!ERRORLEVEL!)
rem      is what makes the real exit code survive.
rem   2. A bare "python" on PATH can be the Microsoft Store alias, which is not
rem      an interpreter. Anything under WindowsApps is skipped.
rem
rem Everything resolves from %~dp0, so the launcher works from any directory.
setlocal enabledelayedexpansion

set "XSSMAP_PY="
for /f "delims=" %%P in ('where python 2^>nul') do (
    set "CAND=%%P"
    rem Absolute path: a developer shell (Git Bash, MSYS) can put a POSIX
    rem `find` first on PATH, and that is a different program with a different
    rem argument syntax.
    echo !CAND! | "%SystemRoot%\System32\find.exe" /i "WindowsApps" >nul || if not defined XSSMAP_PY set "XSSMAP_PY=!CAND!"
)
if not defined XSSMAP_PY (
    for /f "delims=" %%P in ('where py 2^>nul') do (
        if not defined XSSMAP_PY set "XSSMAP_PY=%%P --3"
    )
)
if not defined XSSMAP_PY (
    echo [-] No Python interpreter found on PATH. Install Python 3.9+ from
    echo     https://www.python.org/downloads/windows/ and retry.
    exit /b 2
)

"%XSSMAP_PY%" "%~dp0run.py" %*
set "RC=!ERRORLEVEL!"
if not "!RC!"=="0" (
    rem 2 = usage or environment problem, 130 = interrupted, 1 = findings found
    echo [-] xssmap exited with status !RC! 1>&2
)
exit /b !RC!
