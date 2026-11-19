@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
set ROOT=%~dp0
pushd "%ROOT%"
if not exist obj mkdir obj
cl /nologo /c /W3 /Gd /GX- /GF /Zi /ML /Foobj\ /I src src\xpress.c
if errorlevel 1 goto :fail
cl /nologo /Zi /ML /I src /Feobj\test_xpress.exe test_xpress.c obj\xpress.obj kernel32.lib
if errorlevel 1 goto :fail
pushd testdata
..\obj\test_xpress.exe
set RC=%errorlevel%
popd
popd
if not "%RC%"=="0" goto :fail
endlocal
exit /b 0
:fail
echo === XPRESS TEST FAILED ===
endlocal
exit /b 1
