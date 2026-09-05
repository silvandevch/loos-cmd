@echo off
setlocal
call "C:\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cd /d C:\LoOS\src
if not exist C:\LoOS\out mkdir C:\LoOS\out
echo Building cmd.c ...
cl /nologo /EHsc /O2 /W0 /Fe:C:\LoOS\out\cmd.exe cmd.c ws2_32.lib iphlpapi.lib dnsapi.lib netapi32.lib winhttp.lib advapi32.lib shell32.lib user32.lib kernel32.lib
echo === EXIT CODE: %ERRORLEVEL% ===
dir C:\LoOS\out\cmd.exe