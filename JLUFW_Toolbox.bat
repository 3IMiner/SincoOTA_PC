@echo off
rem JLUFW firmware toolbox launcher
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0jlufw_toolbox.py" %*
) else (
    python "%~dp0jlufw_toolbox.py" %*
)
