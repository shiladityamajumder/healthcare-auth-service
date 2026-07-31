"""Fail CI when tracked release inputs contain forbidden secret artifacts."""

from __future__ import annotations

import subprocess
from pathlib import Path
from shutil import which

_FORBIDDEN_SUFFIXES = {".key", ".p12", ".pem", ".pfx", ".backup", ".dump"}
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    git_executable = which("git")
    if git_executable is None:
        raise RuntimeError("git is required for the release artifact check")
    completed = subprocess.run(  # noqa: S603 - resolved executable, fixed arguments
        [git_executable, "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    tracked = [root / item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]
    violations: list[str] = []
    for path in tracked:
        relative = path.relative_to(root).as_posix()
        name = path.name.casefold()
        if (name == ".env" or name.startswith(".env.")) and name != ".env.example":
            violations.append(relative)
            continue
        if path.suffix.casefold() in _FORBIDDEN_SUFFIXES:
            violations.append(relative)
            continue
        if path.is_file() and any(marker in path.read_bytes() for marker in _PRIVATE_KEY_MARKERS):
            violations.append(relative)

    required_patterns = (".env", ".env.*", "*.key", "*.pem", "*.p12", "*.pfx")
    for ignore_file in (".gitignore", ".dockerignore"):
        ignored = (root / ignore_file).read_text(encoding="utf-8").splitlines()
        for required_pattern in required_patterns:
            if required_pattern not in ignored:
                violations.append(f"{ignore_file} missing {required_pattern}")

    if violations:
        print("Forbidden release artifacts detected:")
        for violation in sorted(set(violations)):
            print(f"- {violation}")
        return 1

    print("Release artifact secret-file check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
