#!/usr/bin/env python3
"""Move only the Android 7.1 adb command child into TWRP recovery domain.

Keep the parent adbd process in the hardware-proven UID/GID 0, u:r:adbd:s0
FunctionFS architecture. After adbd forks a shell-service child, change only
that child to u:r:recovery:s0 and execute the known ramdisk /sbin/sh directly.

Hardware testing established why both halves are required on SM-J720F/CUL1:
* the recovery-only kernel +0x154d18 patch preserves UID/GID 0 across exec; and
* the native TWRP u:r:recovery:s0 domain can enumerate /, write /tmp and read
  kmsg while a root u:r:adbd:s0 command child is still denied those operations.

This keeps USB setup isolated in adbd while giving command execution the same
SELinux domain as TWRP's working touchscreen terminal. Keep explicit /sbin
runtime paths and linker diagnostics until the CI-built artifact is proven.
Fail closed if donor anchors move.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_ADB_RECOVERY_CHILD"
CHILD_MARKER = "J720F_SHELL_CHILD"
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
        '#include <log/log.h>\n#include <stdio.h>\n#include <selinux/android.h>\n#include <selinux/selinux.h>\n',
        "diagnostic/libselinux includes",
    )

    text = replace_once(
        text,
        '    std::vector<std::string> joined_env;\n',
        '''    // Recovery executables and their shared libraries live in /sbin.
    // Pass the recovery runtime paths explicitly to every command child.
    env["PATH"] = "/sbin:/system/bin";
    env["LD_LIBRARY_PATH"] = "/sbin";
    env["SHELL"] = "/sbin/sh";

    std::vector<std::string> joined_env;
''',
        "recovery child environment",
    )

    old = '        std::string shell_command;\n'
    new = r'''        // J720F_ADB_RECOVERY_CHILD: preserve the proven parent adbd USB domain,
        // but move only this already-forked command child into TWRP's working
        // u:r:recovery:s0 domain before executing the ramdisk shell.
        const char* j720f_child_ld = "<absent>";
        for (const char* item : cenv) {
            if (item != nullptr && strncmp(item, "LD_LIBRARY_PATH=", 16) == 0) {
                j720f_child_ld = item + 16;
                break;
            }
        }

        char* j720f_pre_context = nullptr;
        errno = 0;
        const int j720f_pre_getcon = getcon(&j720f_pre_context);
        const int j720f_pre_getcon_errno = j720f_pre_getcon == 0 ? 0 : errno;

        char j720f_child_diag[1024];
        snprintf(j720f_child_diag, sizeof(j720f_child_diag),
                 "J720F_SHELL_CHILD phase=pre_setcon_recovery uid=%d euid=%d gid=%d egid=%d "
                 "context=%s context_errno=%d cenv_ld=%s\n",
                 static_cast<int>(getuid()), static_cast<int>(geteuid()),
                 static_cast<int>(getgid()), static_cast<int>(getegid()),
                 j720f_pre_getcon == 0 && j720f_pre_context != nullptr ? j720f_pre_context : "<unavailable>",
                 j720f_pre_getcon_errno, j720f_child_ld);
        WriteFdExactly(STDERR_FILENO, j720f_child_diag);
        if (j720f_pre_context != nullptr) {
            freecon(j720f_pre_context);
        }

        if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
            WriteFdExactly(child_error_sfd.fd(), "J720F adb command child lost root before recovery setcon");
            child_error_sfd.Reset();
            _Exit(1);
        }

        errno = 0;
        if (selinux_android_setcon("u:r:recovery:s0") < 0) {
            const int saved_errno = errno;
            snprintf(j720f_child_diag, sizeof(j720f_child_diag),
                     "J720F_CHILD_RECOVERY_SELCON failed errno=%d (%s)\n",
                     saved_errno, strerror(saved_errno));
            WriteFdExactly(STDERR_FILENO, j720f_child_diag);
            WriteFdExactly(child_error_sfd.fd(), "J720F_CHILD_RECOVERY_SELCON failed: ");
            WriteFdExactly(child_error_sfd.fd(), strerror(saved_errno));
            child_error_sfd.Reset();
            _Exit(1);
        }

        char* j720f_post_context = nullptr;
        errno = 0;
        const int j720f_post_getcon = getcon(&j720f_post_context);
        const int j720f_post_getcon_errno = j720f_post_getcon == 0 ? 0 : errno;

        const std::string shell_command = "/sbin/sh";
        struct stat j720f_shell_st;
        errno = 0;
        const int j720f_shell_stat = stat(shell_command.c_str(), &j720f_shell_st);
        const int j720f_shell_stat_errno = j720f_shell_stat == 0 ? 0 : errno;
        errno = 0;
        const int j720f_shell_access = access(shell_command.c_str(), X_OK);
        const int j720f_shell_access_errno = j720f_shell_access == 0 ? 0 : errno;

        snprintf(j720f_child_diag, sizeof(j720f_child_diag),
                 "J720F_SHELL_CHILD phase=post_setcon_recovery uid=%d euid=%d gid=%d egid=%d "
                 "context=%s context_errno=%d cenv_ld=%s shell=%s shell_stat=%d shell_stat_errno=%d "
                 "shell_mode=%04o shell_uid=%d shell_gid=%d shell_access=%d shell_access_errno=%d\n",
                 static_cast<int>(getuid()), static_cast<int>(geteuid()),
                 static_cast<int>(getgid()), static_cast<int>(getegid()),
                 j720f_post_getcon == 0 && j720f_post_context != nullptr ? j720f_post_context : "<unavailable>",
                 j720f_post_getcon_errno, j720f_child_ld, shell_command.c_str(),
                 j720f_shell_stat, j720f_shell_stat_errno,
                 j720f_shell_stat == 0 ? static_cast<unsigned int>(j720f_shell_st.st_mode & 07777) : 0,
                 j720f_shell_stat == 0 ? static_cast<int>(j720f_shell_st.st_uid) : -1,
                 j720f_shell_stat == 0 ? static_cast<int>(j720f_shell_st.st_gid) : -1,
                 j720f_shell_access, j720f_shell_access_errno);
        WriteFdExactly(STDERR_FILENO, j720f_child_diag);
        if (j720f_post_context != nullptr) {
            freecon(j720f_post_context);
        }

        if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
            WriteFdExactly(child_error_sfd.fd(), "J720F recovery-domain adb child lost UID/GID 0 before exec");
            child_error_sfd.Reset();
            _Exit(1);
        }
        if (j720f_shell_stat != 0 || j720f_shell_access != 0) {
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

    text = replace_once(
        text,
        '    char propbuf[PATH_MAX];\n',
        '',
        "unused donor shell property buffer",
    )

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
    ):
        if forbidden in text:
            raise RuntimeError(f"superseded command-child context handoff remains: {forbidden}")

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
        "child_diag_marker": CHILD_MARKER,
        "shell_path": SHELL_PATH,
        "explicit_ld_library_path": "/sbin",
        "command_child_setcon": True,
        "target_child_context": TARGET_CONTEXT,
        "command_child_stays_adbd": False,
        "parent_adbd_stays_adbd": True,
        "parent_adbd_root_seclabel": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
