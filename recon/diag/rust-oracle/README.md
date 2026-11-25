# Rust MSDelta diagnostic oracles

These helpers build the two local Rust implementations as diagnostic tools. They do not change the production C build.

The helpers have separate Cargo manifests and lockfiles. Both source packages use the name `msdelta` version `0.1.0`, so Cargo cannot put them in one lockfile.

## Build

Run `build.bat`. The script uses the portable toolchain in `%TEMP%\opencode\rust-portable` by default. Set `RUSTUP_HOME` and `CARGO_HOME` to use another toolchain. The build uses the MinGW tools in `C:\msys64\mingw64\bin`.

## Apply a delta

```bat
napbat\target\release\msdelta-napbat.exe source.bin delta.bin output.bin
jlevere\target\release\msdelta-jlevere.exe apply source.bin delta.bin output.bin
```

`napbat` supports PA30/PA31, raw data, and x86/x64 PE images without .NET metadata. `jlevere` supports PA30/PA31 and partial classic CLI preprocessing. Neither engine supports CIX manifests, IA64, ARM, ARM64, or CLI4.

## Create test deltas

```bat
jlevere\target\release\msdelta-jlevere.exe create source.bin target.bin delta.bin raw
jlevere\target\release\msdelta-jlevere.exe create source.bin target.bin delta.bin auto
jlevere\target\release\msdelta-jlevere.exe create source.bin target.bin delta.bin pa31
jlevere\target\release\msdelta-jlevere.exe create source.bin target.bin delta.bin bsdiff
```

The helper selects SHA-256 for generated deltas. `auto` tries PE preprocessing and falls back to raw data. `pa31` creates a raw PA31 delta. `bsdiff` creates a PA31 BsDiff delta.

## Create a reverse delta

```bat
jlevere\target\release\msdelta-jlevere.exe reverse source.bin delta.bin target.bin reverse.bin
```

This calls jlevere's `apply_get_reverse`. Apply `reverse.bin` to `target.bin` to reconstruct `source.bin`.

## Use as an oracle

Compare all three decoders with one command:

```bat
python compare.py source.bin delta.bin expected.bin
```

The script runs the native C decoder, napbat, and jlevere. It reports unsupported Rust features as `SKIP`. Compare the helper output with `recon\obj\test_delta.exe` or with a manifest SHA256. Treat unsupported-engine errors as coverage gaps, not as native decoder failures.

The source crates are dual-licensed under MIT or Apache-2.0. Keep their license notices if code is copied. Do not vendor Microsoft fixture files that forbid redistribution.
