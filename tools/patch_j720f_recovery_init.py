#!/usr/bin/env python3
"""Patch Android 7.1 recovery init to select SELinux permissive before rc actions."""

from __future__ import annotations

import re
import sys
from pathlib import Path

MARKER = "J720F recovery: forcing SELinux permissive"


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} PATH/TO/init.cpp", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    text = path.read_text()

    if MARKER in text:
        print(f"{path}: recovery SELinux patch already present")
        return 0

    pattern = re.compile(
        r"static\s+bool\s+selinux_is_enforcing\s*\(\s*void\s*\)\s*"
        r"\{\s*"
        r"if\s*\(\s*ALLOW_PERMISSIVE_SELINUX\s*\)\s*\{\s*"
        r"return\s+selinux_status_from_cmdline\s*\(\s*\)\s*==\s*"
        r"SELINUX_ENFORCING\s*;\s*"
        r"\}\s*"
        r"return\s+true\s*;\s*"
        r"\}",
        re.MULTILINE,
    )

    replacement = (
        "static bool selinux_is_enforcing(void)\n"
        "{\n"
        "    (void)selinux_status_from_cmdline();\n"
        f'    INFO("{MARKER}\\n");\n'
        "    return false;\n"
        "}"
    )

    updated, count = pattern.subn(lambda _match: replacement, text, count=1)
    if count != 1:
        print(
            f"{path}: expected exactly one Android 7.1 "
            "selinux_is_enforcing() implementation",
            file=sys.stderr,
        )
        return 1

    path.write_text(updated)
    print(f"{path}: patched recovery init SELinux decision")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
