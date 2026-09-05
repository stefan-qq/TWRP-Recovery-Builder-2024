#!/usr/bin/env python3
"""Use an exec-time recovery transition for PTY adb shell children on J720F."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_ADB_PTY_RECOVERY_EXEC"
TARGET_CONTEXT = "u:r:recovery:s0"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def patch(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("shell_service.cpp is already J720F PTY exec-transition patched")
    if "J720F_ADB_RECOVERY_CHILD" not in text:
        raise RuntimeError("recovery-child patch must run before PTY exec-transition patch")

    fork_anchor = '''    if (type_ == SubprocessType::kPty) {
        int fd;
        pid_ = forkpty(&fd, pts_name, nullptr, nullptr);
        if (pid_ > 0) {
          stdinout_sfd_.Reset(fd);
        }
    } else {
'''
    fork_replacement = '''    // J720F_ADB_PTY_RECOVERY_EXEC: arm the recovery exec context before
    // forkpty(); the PTY child inherits it and the parent clears it below.
    const bool j720f_pty_exec_transition = type_ == SubprocessType::kPty;
    if (j720f_pty_exec_transition) {
        errno = 0;
        if (setexeccon("u:r:recovery:s0") < 0) {
            *error = android::base::StringPrintf(
                "J720F PTY setexeccon(%s) failed: %s", "u:r:recovery:s0", strerror(errno));
            return false;
        }
    }

    if (type_ == SubprocessType::kPty) {
        int fd;
        pid_ = forkpty(&fd, pts_name, nullptr, nullptr);
        if (pid_ > 0) {
          stdinout_sfd_.Reset(fd);
        }
    } else {
'''
    text = replace_once(text, fork_anchor, fork_replacement, "PTY fork transition setup")

    parent_clear_anchor = '''        pid_ = fork();
    }

    if (pid_ == -1) {
'''
    parent_clear_replacement = '''        pid_ = fork();
    }

    // Only the forkpty child retains the pending recovery exec context.
    if (j720f_pty_exec_transition && pid_ != 0) {
        const int j720f_fork_errno = errno;
        errno = 0;
        if (setexeccon(nullptr) < 0) {
            const int j720f_clear_errno = errno;
            if (pid_ > 0) {
                kill(pid_, SIGKILL);
            }
            *error = android::base::StringPrintf(
                "J720F parent failed to clear PTY exec context: %s", strerror(j720f_clear_errno));
            return false;
        }
        errno = j720f_fork_errno;
    }

    if (pid_ == -1) {
'''
    text = replace_once(text, parent_clear_anchor, parent_clear_replacement, "PTY parent setexec clear")

    setcon_anchor = '''        errno = 0;
        if (selinux_android_setcon("u:r:recovery:s0") < 0) {
            const int saved_errno = errno;
            WriteFdExactly(child_error_sfd.fd(), "J720F_CHILD_RECOVERY_SELCON failed: ");
            WriteFdExactly(child_error_sfd.fd(), strerror(saved_errno));
            child_error_sfd.Reset();
            _Exit(1);
        }

'''
    setcon_replacement = '''        if (!j720f_pty_exec_transition) {
            errno = 0;
            if (selinux_android_setcon("u:r:recovery:s0") < 0) {
                const int saved_errno = errno;
                WriteFdExactly(child_error_sfd.fd(), "J720F_CHILD_RECOVERY_SELCON failed: ");
                WriteFdExactly(child_error_sfd.fd(), strerror(saved_errno));
                child_error_sfd.Reset();
                _Exit(1);
            }
        }

'''
    text = replace_once(text, setcon_anchor, setcon_replacement, "raw-vs-PTY recovery handoff")

    text = replace_once(
        text,
        '"J720F recovery-domain adb child lost UID/GID 0 before exec"',
        '"J720F adb child lost UID/GID 0 before exec"',
        "generic pre-exec root failure",
    )
    text = replace_once(
        text,
        '"J720F /sbin/sh is not executable in recovery child domain"',
        '"J720F /sbin/sh is not executable before adb child exec"',
        "generic shell-access failure",
    )

    required = (
        MARKER,
        'setexeccon("u:r:recovery:s0")',
        'setexeccon(nullptr)',
        'selinux_android_setcon("u:r:recovery:s0")',
    )
    for item in required:
        if item not in text:
            raise RuntimeError(f"patched shell_service.cpp missing required marker: {item}")
    if "J720F_SHELL_CHILD phase=" in text:
        raise RuntimeError("success-path shell credential diagnostics remain")
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system-core", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    root = args.system_core.resolve()
    path = root / "adb/shell_service.cpp"
    original = path.read_text()
    patched = patch(original)
    path.write_text(patched)

    report = {
        "source": str(path.relative_to(root)),
        "sha256_before": sha256(original),
        "sha256_after": sha256(patched),
        "required_marker": MARKER,
        "target_context": TARGET_CONTEXT,
        "pty_transition": "setexeccon before forkpty, child inherits, parent clears",
        "raw_transition": "post-fork selinux_android_setcon",
        "parent_adbd_stays_adbd": True,
        "success_path_diagnostics": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
