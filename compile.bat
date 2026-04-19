@echo off
setlocal

if "%GOTOOLCHAIN%"=="" set "GOTOOLCHAIN=auto"

go build -trimpath -ldflags="-s -w" -o uwgsocks.exe ./cmd/uwgsocks
if errorlevel 1 exit /b %errorlevel%

echo COMPILE SUCCEEDED. Built uwgsocks.exe
echo uwgwrapper is Linux/Android-only and is intentionally skipped on Windows.
