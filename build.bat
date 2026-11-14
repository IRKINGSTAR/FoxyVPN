@echo off
rem FoxyVPN-Windows build script (portable build)
setlocal
cd /d "%~dp0"

set TAGS=desktop,production,with_quic,with_utls,with_clash_api
set LDFLAGS=-s -w -H windowsgui

echo [1/3] Building portable FoxyVPN.exe (icon + embedded wintun) ...
go build -trimpath -ldflags "%LDFLAGS%" -tags "%TAGS%" -o build\FoxyVPN-Portable.exe . || goto :err

echo [2/3] Checking wintun.dll ...
if not exist build\wintun.dll (
  echo   downloading wintun 0.14.1 ...
  powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile "$env:TEMP\wintun.zip"" || goto :err
  powershell -NoProfile -Command "Expand-Archive -Force "$env:TEMP\wintun.zip" "$env:TEMP\wintun"" || goto :err
  copy /y "%TEMP%\wintun\wintun\bin\amd64\wintun.dll" build\wintun.dll >nul || goto :err
)
if not exist assets\wintun.dll copy /y build\wintun.dll assets\wintun.dll >nul

echo [3/3] Done.
echo Portable exe: build\FoxyVPN-Portable.exe
echo (wintun.dll is embedded; it is also shipped as a fallback file)
exit /b 0

:err
echo BUILD FAILED
exit /b 1
