@echo off
pushd "%~dp0"
set TD=..\testdata\lzms
echo ---------- v0 ----------
ref_lzms.exe "%TD%\v0_comp.bin" 64 "%TD%\v0_in.bin"
echo ---------- v1 ----------
ref_lzms.exe "%TD%\v1_comp.bin" 512 "%TD%\v1_in.bin"
popd
