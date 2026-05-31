@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Delete Discord Webhooks
cd /d "%~dp0"

echo.
echo ============================================
echo   DELETE DISCORD WEBHOOKS
echo ============================================
echo.
echo Deletes each webhook in: webhooks-to-delete.txt
echo Uses: DELETE https://discord.com/api/webhooks/{id}/{token}
echo.
echo EXCLUDED (never deleted by this script):
echo   Webhook ID 1248156380121272391
echo.

if not exist "%~dp0webhooks-to-delete.txt" (
  echo ERROR: webhooks-to-delete.txt not found.
  pause
  exit /b 1
)

set /p CONFIRM=Type YES to delete all webhooks in the list: 
if /I not "%CONFIRM%"=="YES" (
  echo Cancelled.
  pause
  exit /b 0
)

set COUNT=0
set OK=0
set FAIL=0

for /f "usebackq tokens=* delims=" %%U in ("%~dp0webhooks-to-delete.txt") do (
  set "URL=%%U"
  if not "!URL!"=="" (
    echo !URL! | findstr /I /C:"/webhooks/1248156380121272391/" >nul
    if not errorlevel 1 (
      echo [SKIP] Protected webhook
    ) else (
      set /a COUNT+=1
      for /f %%H in ('curl -s -o "%TEMP%\weehok-del-body.txt" -w "%%{http_code}" -X DELETE "!URL!"') do set "CODE=%%H"
      if "!CODE!"=="204" (
        set /a OK+=1
        echo [!COUNT!] OK 204 - deleted
      ) else if "!CODE!"=="404" (
        set /a FAIL+=1
        echo [!COUNT!] 404 - not found or already deleted
      ) else (
        set /a FAIL+=1
        echo [!COUNT!] HTTP !CODE!
        type "%TEMP%\weehok-del-body.txt" 2>nul
      )
    )
  )
)

echo.
echo Finished. Attempted: %COUNT%  Deleted (204): %OK%  Other: %FAIL%
echo.
pause
endlocal
