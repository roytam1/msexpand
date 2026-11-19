@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT"
pushd "%~dp0"
cl /nologo /ML /Feobj\apply_pa19.exe apply_pa19.c kernel32.lib
cl /nologo /Zi /ML /I src /Feobj\test_delta.exe test_delta.c obj\delta.obj obj\lzx.obj obj\mslzx.obj obj\pefix.obj obj\hash.obj kernel32.lib imagehlp.lib
