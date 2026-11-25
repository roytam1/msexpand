import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def run(command, env=None):
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)


def main():
    if len(sys.argv) != 4:
        print("usage: compare.py <source> <delta> <expected>", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parents[3]
    source = Path(sys.argv[1]).resolve()
    delta = Path(sys.argv[2]).resolve()
    expected = Path(sys.argv[3]).resolve()
    expected_hash = digest(expected)
    engines = {
        "native": [str(root / "recon" / "obj" / "test_delta.exe")],
        "napbat": [str(Path(__file__).parent / "napbat" / "target" / "release" / "msdelta-napbat.exe")],
        "jlevere": [str(Path(__file__).parent / "jlevere" / "target" / "release" / "msdelta-jlevere.exe"), "apply"],
    }

    supported = 0
    failed = False
    with tempfile.TemporaryDirectory(prefix="msdelta-oracle-") as temp:
        for name, command in engines.items():
            output = Path(temp) / f"{name}.bin"
            env = None
            if name == "native":
                import os
                env = os.environ.copy()
                env["PA30_NO_OS"] = "1"
                env["DELTA_OUT"] = str(output)
                result = run(command + [str(delta), str(source), str(expected)], env)
            else:
                result = run(command + [str(source), str(delta), str(output)])

            if result.returncode != 0:
                message = result.stdout.decode("utf-8", "replace").strip().splitlines()
                detail = message[0] if message else f"exit {result.returncode}"
                print(f"{name}: ERROR: {detail}")
                if "unsupported" in detail.lower():
                    print(f"{name}: SKIP (unsupported feature)")
                    continue
                failed = True
                continue

            actual_hash = digest(output)
            if actual_hash == expected_hash:
                print(f"{name}: OK {actual_hash}")
                supported += 1
            else:
                print(f"{name}: MISMATCH {actual_hash}")
                failed = True

    if not supported:
        print("no supported engine produced output", file=sys.stderr)
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
