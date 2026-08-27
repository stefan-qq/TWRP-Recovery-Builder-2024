#!/usr/bin/env python3
"""Run the Android 7.1 adbd command child in the recovery SELinux domain.

The Samsung CUL1 kernel presents an exec from u:r:shell:s0 to linker64 with
UID/GID 2000 even though the root adbd child is UID/GID 0 immediately before
exec. Recovery /sbin is intentionally root-owned 0750, so that exec-time
credential change prevents linker64 from opening /sbin/libc.so.

Keep the adbd parent in u:r:adbd:s0, move only the forked command child to the
already-proven u:r:recovery:s0 domain, and pass the recovery /sbin runtime paths
explicitly in the child's exec environment. Fail closed if donor anchors move.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_RECOVERY_SHELL_SELCON"
CHILD_MARKER = "J720F_SHELL_CHILD"
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
        raise RuntimeError("shell_service.cpp is already recovery-shell patched")

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
        '#include <log/log.h>\n#include <stdio.h>\n#include <selinux/android.h>\n',
        "libselinux include",
    )

    text = replace_once(
        text,
        '    std::vector<std::string> joined_env;\n',
        '''    // Recovery executables and their shared libraries live in /sbin.
    // adbd's live C environ does not retain init's LD_LIBRARY_PATH even though
    // /proc/self/environ still exposes the original process-start environment.
    // Pass the runtime paths explicitly to the exec child.
    env["PATH"] = "/sbin:/system/bin";
    env["LD_LIBRARY_PATH"] = "/sbin";

    std::vector<std::string> joined_env;
''',
        "recovery child environment",
    )

    old = '''        std::string shell_command;\n'''
    new = '''        // Keep the parent adbd in u:r:adbd:s0 so the proven FunctionFS
        // transport and sync service are unchanged. On this Samsung kernel an
        // exec from u:r:shell:s0 is presented to linker64 as UID/GID 2000 even
        // though this child is UID/GID 0 immediately before exec. TWRP /sbin is
        // root-owned 0750, so run only the command child in recovery domain.
        const char* j720f_child_ld = "<absent>";
        for (const char* item : cenv) {
            if (item != nullptr && strncmp(item, "LD_LIBRARY_PATH=", 16) == 0) {
                j720f_child_ld = item + 16;
                break;
            }
        }
        char j720f_child_diag[640];
        snprintf(j720f_child_diag, sizeof(j720f_child_diag),
                 "J720F_SHELL_CHILD phase=pre_setcon uid=%d euid=%d gid=%d egid=%d cenv_ld=%s\\n",
                 static_cast<int>(getuid()), static_cast<int>(geteuid()),
                 static_cast<int>(getgid()), static_cast<int>(getegid()),
                 j720f_child_ld);
        WriteFdExactly(STDERR_FILENO, j720f_child_diag);

        errno = 0;
        if (selinux_android_setcon("u:r:recovery:s0") < 0) {
            const int saved_errno = errno;
            WriteFdExactly(child_error_sfd.fd(),
                           "J720F_RECOVERY_SHELL_SELCON failed: " );
            WriteFdExactly(child_error_sfd.fd(), strerror(saved_errno));
            child_error_sfd.Reset();
            _Exit(1);
        }

        struct stat j720f_sbin_st;
        const int j720f_sbin_stat = stat("/sbin", &j720f_sbin_st);
        errno = 0;
        const int j720f_libc_access = access("/sbin/libc.so", R_OK);
        const int j720f_libc_errno = j720f_libc_access == 0 ? 0 : errno;
        snprintf(j720f_child_diag, sizeof(j720f_child_diag),
                 "J720F_SHELL_CHILD phase=post_setcon uid=%d euid=%d gid=%d egid=%d cenv_ld=%s "
                 "sbin_stat=%d sbin_mode=%04o sbin_uid=%d sbin_gid=%d libc_access=%d libc_errno=%d\\n",
                 static_cast<int>(getuid()), static_cast<int>(geteuid()),
                 static_cast<int>(getgid()), static_cast<int>(getegid()),
                 j720f_child_ld, j720f_sbin_stat,
                 j720f_sbin_stat == 0 ? static_cast<unsigned int>(j720f_sbin_st.st_mode & 07777) : 0,
                 j720f_sbin_stat == 0 ? static_cast<int>(j720f_sbin_st.st_uid) : -1,
                 j720f_sbin_stat == 0 ? static_cast<int>(j720f_sbin_st.st_gid) : -1,
                 j720f_libc_access, j720f_libc_errno);
        WriteFdExactly(STDERR_FILENO, j720f_child_diag);

        std::string shell_command;
'''
    text = replace_once(text, old, new, "recovery shell setcon")

    old_exec = '''        if (command_.empty()) {
            execle(shell_command.c_str(), shell_command.c_str(), "-", nullptr, cenv.data());
'''
    new_exec = '''        snprintf(j720f_child_diag, sizeof(j720f_child_diag),
                 "J720F_SHELL_CHILD phase=pre_exec uid=%d euid=%d gid=%d egid=%d cenv_ld=%s shell=%s\\n",
                 static_cast<int>(getuid()), static_cast<int>(geteuid()),
                 static_cast<int>(getgid()), static_cast<int>(getegid()),
                 j720f_child_ld, shell_command.c_str());
        WriteFdExactly(STDERR_FILENO, j720f_child_diag);

        if (command_.empty()) {
            execle(shell_command.c_str(), shell_command.c_str(), "-", nullptr, cenv.data());
'''
    text = replace_once(text, old_exec, new_exec, "pre-exec credential trace")
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
        "child_diag_marker": CHILD_MARKER,
        "explicit_ld_library_path": "/sbin",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
