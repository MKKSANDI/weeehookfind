@echo off
setlocal
cd /d "%~dp0terminal"
python run_weehook_terminal.py %*
endlocal
