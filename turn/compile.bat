@echo off
setlocal

if "%GOTOOLCHAIN%"=="" set "GOTOOLCHAIN=auto"

go build -trimpath -ldflags="-s -w" -o turn.exe .
if errorlevel 1 exit /b %errorlevel%

echo COMPILE SUCCEEDED. Built turn.exe
