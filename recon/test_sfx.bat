@echo off
rem SFX regression harness: unpack the IE6 SP1 hotfix with the native PA19
rem decoder and compare every patched binary with the SFX-run ground truth.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT" >NUL
pushd "%~dp0"
set SFX=..\IE6.0SP1-KB2722913-WINDOWS2000-X86-CHT.EXE
set GOLD=..\IE6.0SP1-KB2722913-WINDOWS2000-X86-CHT-sfxrun\RTMQFE
if not exist "%SFX%" goto :skip
if not exist "%GOLD%" goto :skip
if not exist expand_recon.exe call build.bat >NUL
if errorlevel 1 goto :fail

if exist testdata\sfxout rmdir /s /q testdata\sfxout
mkdir testdata\sfxout
set PA19_NO_OS=1
expand_recon.exe "%SFX%" -F:* testdata\sfxout >NUL
set PA19_NO_OS=
if errorlevel 1 goto :fail

echo === SFX: native PA19 vs SFX RTMQFE ===
set BAD=0
for %%P in (browseui cdfview danim dxtmsft dxtrans iepeers inseng jsproxy mshtml mshtmled msrating mstime pngfilt shdocvw shlwapi urlmon wininet) do (
  fc /b "testdata\sfxout\RTMQFE\%%P.dll" "%GOLD%\%%P.dll" >NUL
  if errorlevel 1 set BAD=1
)
fc /b "testdata\sfxout\RTMQFE\tdc.ocx" "%GOLD%\tdc.ocx" >NUL
if errorlevel 1 set BAD=1
rem [Delete] is applied by the run: the patch files and the stub DLL must be gone.
for /f %%A in ('dir /b /s /a-d testdata\sfxout\*._p 2^>NUL') do set BAD=1
if exist "testdata\sfxout\_sfx_.dll" set BAD=1
if "%BAD%"=="1" goto :fail
echo === SFX tests done ===
popd
endlocal
exit /b 0

:skip
echo === SFX test inputs not present: skipped ===
popd
endlocal
exit /b 0

:fail
echo === SFX TEST FAILURE ===
popd
endlocal
exit /b 1
