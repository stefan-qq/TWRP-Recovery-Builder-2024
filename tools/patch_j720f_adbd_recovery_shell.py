#!/usr/bin/env python3
"""Keep the Android 7.1 adb command child in stock recovery's root su domain.

Samsung CUL1 stock recovery starts adbd as u:r:adbd:s0 with
--root_seclabel=u:r:su:s0. The pinned Android 7.1 adbd already implements that
option: after it decides to remain UID 0, the *parent adbd process* setcon()s to
the supplied root label before USB initialization and before serving commands.

Earlier J720F experiments instead moved each command child into shell/recovery
immediately before exec. Hardware tracing proved that the Samsung kernel then
presents the new ELF image as UID/GID 2000 even though the child is UID/GID 0
at the execle() boundary. Reproduce the stock recovery architecture instead:
leave the forked child in the root adbd domain it inherits (expected u:r:su:s0)
and only make the recovery /sbin runtime environment explicit.

This patch is intentionally diagnostic-friendly: it records the inherited
credentials/context and /sbin readability immediately before exec, but it does
not call setcon() in the command child. Fail closed if donor anchors move.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_STOCK_ROOT_SECLABEL_CHILD"
CHILD_MARKER = "J720F_SHELL_CHILD"
EXPECTED_CONTEXT = "u:r:su:s0"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def patch_shell_service(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("shell_service.cpp is already stock-root-seclabel patched")

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
        "libselinux include",
    )

    text = replace_once(
        text,
        '    std::vector<std::string> joined_env;\n',
        '''    // Recovery executables and their shared libraries live in /sbin.
    // adbd's live C environ does not retain init's LD_LIBRARY_PATH even though
    // /proc/self/environ exposes the process-start environment. Pass the
    // recovery runtime paths explicitly to the command child.
    env["PATH"] = "/sbin:/system/bin";
    env["LD_LIBRARY_PATH"] = "/sbin";

    std::vector<std::string> joined_env;
''',
        "recovery child environment",
    )

    old = '        std::string shell_command;\n'
    new = '''        // J720F_STOCK_ROOT_SECLABEL_CHILD: do not setcon() here.
        // CUL1 stock recovery has already moved the root adbd parent from
        // u:r:adbd:s0 to u:r:su:s0 via --root_seclabel, so the command child
        // must inherit that stock root context through exec.
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

        struct stat j720f_sbin_st;
        const int j720f_sbin_stat = stat("/sbin", &j720f_sbin_st);
        errno = 0;
        const int j720f_libc_access = access("/sbin/libc.so", R_OK);
        const int j720f_libc_errno = j720f_libc_access == 0 ? 0 : errno;

        char j720f_child_diag[768];
        snprintf(j720f_child_diag, sizeof(j720f_child_diag),
                 "J720F_SHELL_CHILD phase=inherited_root_seclabel uid=%d euid=%d gid=%d egid=%d "
                 "context=%s context_errno=%d cenv_ld=%s sbin_stat=%d sbin_mode=%04o "
                 "sbin_uid=%d sbin_gid=%d libc_access=%d libc_errno=%d\\n",
                 static_cast<int>(getuid()), static_cast<int>(geteuid()),
                 static_cast<int>(getgid()), static_cast<int>(getegid()),
                 j720f_getcon == 0 && j720f_child_context != nullptr ? j720f_child_context : "<unavailable>",
                 j720f_getcon_errno, j720f_child_ld, j720f_sbin_stat,
                 j720f_sbin_stat == 0 ? static_cast<unsigned int>(j720f_sbin_st.st_mode & 07777) : 0,
                 j720f_sbin_stat == 0 ? static_cast<int>(j720f_sbin_st.st_uid) : -1,
                 j720f_sbin_stat == 0 ? static_cast<int>(j720f_sbin_st.st_gid) : -1,
                 j720f_libc_access, j720f_libc_errno);
        WriteFdExactly(STDERR_FILENO, j720f_child_diag);
        if (j720f_child_context != nullptr) {
            freecon(j720f_child_context);
        }

        std::string shell_command;
'''
    text = replace_once(text, old, new, "stock root-seclabel child trace")

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
        "expected_inherited_context": EXPECTED_CONTEXT,
        "required_marker": MARKER,
        "child_diag_marker": CHILD_MARKER,
        "explicit_ld_library_path": "/sbin",
        "command_child_setcon": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
