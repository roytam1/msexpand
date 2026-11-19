@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
set ROOT=%~dp0
pushd "%ROOT%"
if not exist obj mkdir obj
if not exist testdata\lzms mkdir testdata\lzms
cl /nologo /Zi /ML /I src /Feobj\gen_lzms.exe gen_lzms.c kernel32.lib
if errorlevel 1 goto :fail
cl /nologo /c /W3 /Gd /GX- /GF /Zi /ML /Foobj\ /I src src\lzms.c
if errorlevel 1 goto :fail
cl /nologo /Zi /ML /I src /Feobj\test_lzms.exe test_lzms.c obj\lzms.obj kernel32.lib
if errorlevel 1 goto :fail
pushd testdata
..\obj\gen_lzms.exe
if errorlevel 1 goto :fail
..\obj\test_lzms.exe
set RC=%errorlevel%
popd
popd
if not "%RC%"=="0" goto :fail
endlocal
exit /b 0
:fail
echo === LZMS TEST FAILED ===
endlocal
exit /b 1
