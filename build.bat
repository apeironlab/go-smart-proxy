@echo off
setlocal
cd /d "%~dp0"

echo [1/2] Build web UI...
pushd webui
if not exist node_modules call npm install || goto :fail
call npm run build || goto :fail
popd

echo [2/2] Build proxy.exe...
go build -ldflags "-H=windowsgui" -o proxy.exe . || goto :fail

echo OK: proxy.exe
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
