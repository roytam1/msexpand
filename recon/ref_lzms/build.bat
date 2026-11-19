@echo off
rem Standalone MSVC6 (VC98) build of wimlib 1.14.5's original LZMS decompressor.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
if errorlevel 1 goto :fail

rem UNC working directories need pushd rather than cd /d.
pushd "%~dp0"

echo === Compiling / linking with cl /ML ===
cl /nologo /ML /W3 /Gd /I. /Feref_lzms.exe ^
   main.c lzms_common.c decompress_common.c compress_common.c
if errorlevel 1 goto :fail_unwind

echo === Build OK: ref_lzms.exe ===
popd
endlocal
exit /b 0

:fail_unwind
popd
:fail
echo === BUILD FAILED ===
endlocal
exit /b 1
