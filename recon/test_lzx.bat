@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT" >nul
pushd "%~dp0"
if not exist obj mkdir obj
cl /nologo /c /ML /W3 /Gd /I src /Foobj\ src\lzx.c
if errorlevel 1 goto :fail
cl /nologo /c /ML /W3 /Gd /I src /Fotest_lzx.obj test_lzx.c
if errorlevel 1 goto :fail
link /nologo /subsystem:console /out:test_lzx.exe test_lzx.obj obj\lzx.obj
if errorlevel 1 goto :fail
set TD=testdata\lzx
test_lzx.exe %TD%\cab_block.bin %TD%\cab_expected.bin 54 15
popd
endlocal
exit /b 0
:fail
popd
endlocal
exit /b 1
