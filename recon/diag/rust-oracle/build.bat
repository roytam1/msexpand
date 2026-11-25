@echo off
setlocal
if not defined RUSTUP_HOME set RUSTUP_HOME=%TEMP%\opencode\rust-portable\rustup
if not defined CARGO_HOME set CARGO_HOME=%TEMP%\opencode\rust-portable\cargo
set PATH=C:\msys64\mingw64\bin;%CARGO_HOME%\bin;%PATH%
pushd "%~dp0"
cargo build --release --manifest-path napbat\Cargo.toml
if errorlevel 1 goto :fail
cargo build --release --manifest-path jlevere\Cargo.toml
if errorlevel 1 goto :fail
popd
exit /b 0
:fail
popd
exit /b 1
