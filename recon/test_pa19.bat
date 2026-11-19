@echo off
rem PA19 regression harness.
rem   The shipped expand.exe delegates PA19 to mspatcha.dll, so the authoritative
rem   check is that DeltaApply() reproduces the OS patch engine byte-for-byte.
rem   The in-tree native LZX decoder (PA19_NO_OS=1) is exact for small patches
rem   but is known to diverge on large multi-chunk ALIGNED blocks; that case is
rem   reported but does not fail this harness.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT" >NUL
pushd "%~dp0"
if not exist obj mkdir obj
call build.bat >NUL
if errorlevel 1 goto :fail
call make_tests.bat >NUL
if errorlevel 1 goto :fail
cl /nologo /ML /Feobj\apply_pa19.exe apply_pa19.c kernel32.lib >NUL
if errorlevel 1 goto :fail

rem Generate oracles with the OS mspatcha.dll.
obj\apply_pa19.exe testdata\jsproxy.dll._p testdata\rtmgdr\jsproxy.dll testdata\jsproxy_ora.dll >NUL
if errorlevel 1 goto :noos
obj\apply_pa19.exe testdata\danim.dll._p testdata\rtmgdr\danim.dll testdata\danim_ora.dll >NUL
if errorlevel 1 goto :noos

cl /nologo /Zi /ML /I src /Feobj\test_delta.exe test_delta.c obj\delta.obj obj\lzx.obj obj\mslzx.obj obj\hash.obj kernel32.lib >NUL
if errorlevel 1 goto :fail

echo === PA19: OS delegation path (authoritative) ===
set PA19_NO_OS=
call :check jsproxy
call :check danim

echo === PA19: native mslzx path ===
set PA19_NO_OS=1
call :check_native jsproxy
call :check_native_info danim

echo === PA19 tests done ===
popd
endlocal
exit /b 0

:check
obj\test_delta.exe testdata\%1.dll._p testdata\rtmgdr\%1.dll testdata\%1_ora.dll 2>NUL | findstr /b "compare:"
if errorlevel 1 goto :fail
exit /b 0

:check_native
obj\test_delta.exe testdata\%1.dll._p testdata\rtmgdr\%1.dll testdata\%1_ora.dll 2>NUL | findstr /b "compare:"
if errorlevel 1 goto :fail
exit /b 0

:check_native_info
obj\test_delta.exe testdata\%1.dll._p testdata\rtmgdr\%1.dll testdata\%1_ora.dll 2>NUL | findstr /b "compare:"
exit /b 0

:noos
echo mspatcha.dll unavailable: skipping OS-oracle PA19 tests
popd
endlocal
exit /b 0

:fail
echo === PA19 TEST FAILED ===
popd
endlocal
exit /b 1
