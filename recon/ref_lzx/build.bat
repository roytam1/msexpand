@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
if errorlevel 1 goto :fail
pushd "%~dp0"
cl /nologo /ML /W3 /Gd /I. /Feref_lzx.exe main.c lzx_common.c decompress_common.c
if errorlevel 1 goto :fail_unwind
echo === Build OK: ref_lzx.exe ===
popd
endlocal
exit /b 0
:fail_unwind
popd
:fail
echo === BUILD FAILED ===
endlocal
exit /b 1
