#!/usr/bin/env python3
"""Add the recovery rootfs -> shell SELinux handoff to Android 7.1 adbd.

The pinned donor adbd predates AOSP's recovery-specific shell subprocess
setcon(). In this recovery /sbin/sh is rootfs-labelled, so a child left in the
adbd domain reaches execle() but receives EACCES under enforcing SELinux.

Patch only shell_service.cpp and fail closed if the exact donor anchors move.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_RECOVERY_SHELL_SELCON"
TARGET_CONTEXT = "u:r:shell:s0"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def patch_shell_service(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("shell_service.cpp is already recovery-shell patched")

    for anchor in (
        '#include <log/log.h>',
        'std::string shell_command;',
        'execle(shell_command.c_str(), shell_command.c_str(), "-", nullptr, cenv.data());',
        'execle(shell_command.c_str(), shell_command.c_str(), "-c", command_.c_str(), nullptr, cenv.data());',
    ):
        if anchor not in text:
            raise RuntimeError(f"shell_service.cpp missing anchor: {anchor}")

    text = replace_once(
        text,
        '#include <log/log.h>\n',
        '#include <log/log.h>\n#include <selinux/android.h>\n',
        "libselinux include",
    )

    old = '''        std::string shell_command;\n'''
    new = '''        // Recovery rootfs binaries, including /sbin/sh, are labelled rootfs.\n        // Newer AOSP recovery adbd explicitly moves only the forked shell child\n        // from adbd to shell before exec. Keep the parent adbd in u:r:adbd:s0\n        // so the proven FunctionFS transport and sync service are unchanged.\n        errno = 0;\n        if (selinux_android_setcon("u:r:shell:s0") < 0) {\n            const int saved_errno = errno;\n            WriteFdExactly(child_error_sfd.fd(),\n                           "J720F_RECOVERY_SHELL_SELCON failed: ");\n            WriteFdExactly(child_error_sfd.fd(), strerror(saved_errno));\n            child_error_sfd.Reset();\n            _Exit(1);\n        }\n\n        std::string shell_command;\n'''
    text = replace_once(text, old, new, "recovery shell setcon")
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system-core", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    root = args.system_core.resolve()
    path = root / "adb/shell_service.cpp"
    if not path.is_file():
        raise SystemExit(f"missing source file: {path}")

    original = path.read_text()
    patched = patch_shell_service(original)
    path.write_text(patched)

    report = {
        "source": str(path.relative_to(root)),
        "sha256_before": sha256(original),
        "sha256_after": sha256(patched),
        "target_context": TARGET_CONTEXT,
        "required_marker": MARKER,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
