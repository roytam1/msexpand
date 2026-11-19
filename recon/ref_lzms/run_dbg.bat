@echo off
set LZMS_DBG=1
ref_lzms.exe ..\testdata\lzms\v0_comp.bin 64 ..\testdata\lzms\v0_in.bin 2>r.log 1>nul
