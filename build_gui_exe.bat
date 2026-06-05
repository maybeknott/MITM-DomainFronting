@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 scripts\build_gui_exe.py
) else (
  python scripts\build_gui_exe.py
)

if %ERRORLEVEL% neq 0 (
  echo.
  echo Build failed. Review the output above.
  pause
  exit /b %ERRORLEVEL%
)

echo.
echo Build complete.
echo Open dist\Xray-Cooperative-Overlay-Control-Center and double-click Xray-Cooperative-Overlay-Control-Center.exe
pause
