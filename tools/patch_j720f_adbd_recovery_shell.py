#!/usr/bin/env python3
"""Move only Android 7.1 adb command children into the TWRP recovery domain."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_ADB_RECOVERY_CHILD"
SHELL_PATH = "/sbin/sh"
TARGET_CONTEXT = "u:r:recovery:s0"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def patch_shell_service(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("shell_service.cpp is already J720F recovery-child patched")

    for anchor in (
        '#include <log/log.h>',
        'std::vector<std::string> joined_env;',
        'std::string shell_command;',
        'execle(shell_command.c_str(), shell_command.c_str(), "-", nullptr, cenv.data());',
        'execle(shell_command.c_str(), shell_command.c_str(), "-c", command_.c_str(), nullptr, cenv.data());',
    ):
        if anchor not in text:
            raise RuntimeError(f"shell_service.cpp missing anchor: {anchor}")

    text = replace_once(
        text,
        '#include <log/log.h>\n',
        '#include <log/log.h>\n#include <selinux/android.h>\n#include <selinux/selinux.h>\n',
        "libselinux include",
    )

    text = replace_once(
        text,
        '    std::vector<std::string> joined_env;\n',
        '''    // Recovery executables and their shared libraries live in /sbin.
    env["PATH"] = "/sbin:/system/bin";
    env["LD_LIBRARY_PATH"] = "/sbin";
    env["SHELL"] = "/sbin/sh";

    std::vector<std::string> joined_env;
''',
        "recovery child environment",
    )

    old = '        std::string shell_command;\n'
    new = r'''        // J720F_ADB_RECOVERY_CHILD: preserve the proven parent adbd USB domain,
        // but move only this command child into TWRP's recovery domain.
        if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
            WriteFdExactly(child_error_sfd.fd(), "J720F adb command child lost UID/GID 0 before recovery setcon");
            child_error_sfd.Reset();
            _Exit(1);
        }

        errno = 0;
        if (selinux_android_setcon("u:r:recovery:s0") < 0) {
            const int saved_errno = errno;
            WriteFdExactly(child_error_sfd.fd(), "J720F_CHILD_RECOVERY_SELCON failed: ");
            WriteFdExactly(child_error_sfd.fd(), strerror(saved_errno));
            child_error_sfd.Reset();
            _Exit(1);
        }

        const std::string shell_command = "/sbin/sh";
        if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
            WriteFdExactly(child_error_sfd.fd(), "J720F recovery-domain adb child lost UID/GID 0 before exec");
            child_error_sfd.Reset();
            _Exit(1);
        }
        if (access(shell_command.c_str(), X_OK) != 0) {
            WriteFdExactly(child_error_sfd.fd(), "J720F /sbin/sh is not executable in recovery child domain");
            child_error_sfd.Reset();
            _Exit(1);
        }

'''
    text = replace_once(text, old, new, "recovery-domain command child")

    selector = '''        struct stat st;
        property_get("persist.sys.adb.shell", propbuf, "");
        if (propbuf[0] != '\\0' && stat(propbuf, &st) == 0) {
            shell_command = propbuf;
        } else if (stat(_PATH_BSHELL2, &st) == 0) {
            shell_command = _PATH_BSHELL2;
        } else {
            shell_command = _PATH_BSHELL;
        }

'''
    text = replace_once(text, selector, "", "donor shell path selector")
    text = replace_once(text, '    char propbuf[PATH_MAX];\n', '', "unused donor shell property buffer")

    old_exec = '''        if (command_.empty()) {
            execle(shell_command.c_str(), shell_command.c_str(), "-", nullptr, cenv.data());
'''
    if text.count(old_exec) != 1:
        raise RuntimeError("recovery shell exec anchor moved")

    if text.count('selinux_android_setcon("u:r:recovery:s0")') != 1:
        raise RuntimeError("expected exactly one recovery child setcon")
    for forbidden in (
        'selinux_android_setcon("u:r:shell:s0")',
        'selinux_android_setcon("u:r:su:s0")',
        "J720F_SHELL_CHILD phase=",
    ):
        if forbidden in text:
            raise RuntimeError(f"superseded/diagnostic command-child code remains: {forbidden}")
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
        "required_marker": MARKER,
        "shell_path": SHELL_PATH,
        "explicit_ld_library_path": "/sbin",
        "command_child_setcon": True,
        "target_child_context": TARGET_CONTEXT,
        "parent_adbd_stays_adbd": True,
        "success_path_diagnostics": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
