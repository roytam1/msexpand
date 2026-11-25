@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
set ROOT=%~dp0
pushd "%ROOT%"
if not exist obj mkdir obj
call build.bat >NUL
if errorlevel 1 goto :fail
cl /nologo /Zi /ML /I src /Feobj\test_arm32hint.exe test_arm32hint.c ^
   obj\lzx.obj obj\mslzx.obj obj\pefix.obj obj\hash.obj kernel32.lib imagehlp.lib
if errorlevel 1 goto :fail
obj\test_arm32hint.exe
set RC=%errorlevel%
popd
if not "%RC%"=="0" goto :fail
endlocal
exit /b 0
:fail
echo === ARM32 HINT TEST FAILED ===
endlocal
exit /b 1
