@echo off
rem C89 reconstruction of expand.exe -- MSVC6 build
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
if errorlevel 1 goto :fail

pushd "%~dp0"

if not exist obj mkdir obj

echo === Compiling ===
cl /nologo /c /W3 /Gd /GX- /GF /Zi /ML /Foobj\ /I src /I ..\src ^
   src\expand.c src\messages.c src\util.c src\lz.c src\cab.c src\dpx.c ^
   src\hash.c src\xml.c src\cix.c src\psf.c src\xpress.c src\lzms.c ^
   src\delta.c src\lzx.c src\mslzx.c
if errorlevel 1 goto :fail

echo === Linking ===
link /nologo /subsystem:console /out:expand_recon.exe ^
   obj\expand.obj obj\messages.obj obj\util.obj obj\lz.obj obj\cab.obj obj\dpx.obj ^
   obj\hash.obj obj\xml.obj obj\cix.obj obj\psf.obj obj\xpress.obj obj\lzms.obj ^
   obj\delta.obj obj\lzx.obj obj\mslzx.obj ^
   kernel32.lib user32.lib advapi32.lib
if errorlevel 1 goto :fail

echo === Build OK: expand_recon.exe ===
popd
endlocal
exit /b 0

:fail
echo === BUILD FAILED ===
popd
endlocal
exit /b 1
