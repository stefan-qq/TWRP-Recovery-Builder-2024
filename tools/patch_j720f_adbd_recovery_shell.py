#!/usr/bin/env python3
"""Keep the Android 7.1 adb command child in the proven root adbd domain.

The J720F USB transport is already proven with the parent daemon running as
UID/GID 0 in u:r:adbd:s0. Hardware testing also disproved moving either the
whole daemon or only the command child into alternate SELinux domains: those
experiments either broke FunctionFS before enumeration or made recovery-shell
exec fail before a usable command process existed.

Use a recovery-specific pragmatic model instead: keep the forked command child
in the same u:r:adbd:s0 domain and execute the known ramdisk shell /sbin/sh
directly. The device policy grants only rootfs read/execute-no-transition access
needed for the ramdisk shell and linker. This avoids every per-command setcon()
and avoids the nonexistent /system/bin/sh fallback.

The first hardware build intentionally keeps credential/linker diagnostics so
we can verify that UID/EUID and AT_UID/AT_EUID remain 0 across exec. Fail closed
if donor anchors move.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_ADBD_ROOT_SHELL"
CHILD_MARKER = "J720F_SHELL_CHILD"
SHELL_PATH = "/sbin/sh"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def patch_shell_service(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("shell_service.cpp is already J720F root-shell patched")

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
        '#include <log/log.h>\n#include <stdio.h>\n#include <selinux/selinux.h>\n',
        "diagnostic includes",
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
    new = r'''        // J720F_ADBD_ROOT_SHELL: do not setcon() this forked command child.
        // The parent and child both remain UID/GID 0 in u:r:adbd:s0. Executing
        // /sbin/sh with execute_no_trans avoids the Samsung exec-time credential
        // regressions seen after shell/recovery/su context handoffs.
        const char* j720f_child_ld = "<absent>";
        for (const char* item : cenv) {
            if (item != nullptr && strncmp(item, "LD_LIBRARY_PATH=", 16) == 0) {
                j720f_child_ld = item + 16;
                break;
            }
        }

        char* j720f_child_context = nullptr;
        errno = 0;
        const int j720f_getcon = getcon(&j720f_child_context);
        const int j720f_getcon_errno = j720f_getcon == 0 ? 0 : errno;

        const std::string shell_command = "/sbin/sh";
        struct stat j720f_shell_st;
        errno = 0;
        const int j720f_shell_stat = stat(shell_command.c_str(), &j720f_shell_st);
        const int j720f_shell_stat_errno = j720f_shell_stat == 0 ? 0 : errno;
        errno = 0;
        const int j720f_shell_access = access(shell_command.c_str(), X_OK);
        const int j720f_shell_access_errno = j720f_shell_access == 0 ? 0 : errno;

        char j720f_child_diag[1024];
        snprintf(j720f_child_diag, sizeof(j720f_child_diag),
                 "J720F_SHELL_CHILD phase=adbd_root_pre_exec uid=%d euid=%d gid=%d egid=%d "
                 "context=%s context_errno=%d cenv_ld=%s shell=%s shell_stat=%d shell_stat_errno=%d "
                 "shell_mode=%04o shell_uid=%d shell_gid=%d shell_access=%d shell_access_errno=%d\n",
                 static_cast<int>(getuid()), static_cast<int>(geteuid()),
                 static_cast<int>(getgid()), static_cast<int>(getegid()),
                 j720f_getcon == 0 && j720f_child_context != nullptr ? j720f_child_context : "<unavailable>",
                 j720f_getcon_errno, j720f_child_ld, shell_command.c_str(),
                 j720f_shell_stat, j720f_shell_stat_errno,
                 j720f_shell_stat == 0 ? static_cast<unsigned int>(j720f_shell_st.st_mode & 07777) : 0,
                 j720f_shell_stat == 0 ? static_cast<int>(j720f_shell_st.st_uid) : -1,
                 j720f_shell_stat == 0 ? static_cast<int>(j720f_shell_st.st_gid) : -1,
                 j720f_shell_access, j720f_shell_access_errno);
        WriteFdExactly(STDERR_FILENO, j720f_child_diag);
        if (j720f_child_context != nullptr) {
            freecon(j720f_child_context);
        }

        // A recovery ADB shell must never silently degrade to the Android shell
        // UID. Fail before exec if the proven root parent stopped being root.
        if (getuid() != 0 || geteuid() != 0) {
            WriteFdExactly(child_error_sfd.fd(), "J720F root adb child lost UID 0 before exec");
            child_error_sfd.Reset();
            _Exit(1);
        }
        if (j720f_shell_stat != 0 || j720f_shell_access != 0) {
            WriteFdExactly(child_error_sfd.fd(), "J720F /sbin/sh is not executable in adbd domain");
            child_error_sfd.Reset();
            _Exit(1);
        }

'''
    text = replace_once(text, old, new, "root adbd command child")

    # The donor shell selector follows this anchor. Remove that entire selector;
    # this recovery always owns a known /sbin/sh and must not fall back to
    # /system/bin/sh or a property-controlled executable.
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

    # The donor selector's PATH_MAX property buffer becomes dead once the
    # property-controlled shell path is removed. This tree builds adbd with
    # -Werror, so remove the declaration as part of the same transformation.
    text = replace_once(
        text,
        '    char propbuf[PATH_MAX];\n',
        '',
        "unused donor shell property buffer",
    )

    old_exec = '''        if (command_.empty()) {
            execle(shell_command.c_str(), shell_command.c_str(), "-", nullptr, cenv.data());
'''
    new_exec = '''        if (command_.empty()) {
            execle(shell_command.c_str(), shell_command.c_str(), "-", nullptr, cenv.data());
'''
    # Keep an explicit anchor check even though no text change is needed here.
    if text.count(old_exec) != 1:
        raise RuntimeError("root shell exec anchor moved")

    # Absolutely no per-command SELinux handoff is allowed in this patch.
    for forbidden in (
        'selinux_android_setcon("u:r:shell:s0")',
        'selinux_android_setcon("u:r:recovery:s0")',
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
        "command_child_setcon": False,
        "command_child_stays_adbd": True,
        "parent_adbd_root_seclabel": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
