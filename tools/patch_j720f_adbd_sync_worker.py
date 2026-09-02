#!/usr/bin/env python3
"""Isolate the legacy adb sync service in a recovery-domain helper on J720F.

The USB daemon must remain in u:r:adbd:s0. Hardware proves that command children
in u:r:recovery:s0 have normal recovery filesystem access, while the in-process
legacy file_sync_service thread in adbd cannot create/read ordinary recovery
paths. Launch sync through a tiny fork+exec boundary instead: the service thread
arms a recovery exec context, forks, immediately clears that pending context in
the parent, and the child self-execs /sbin/adbd with only the sync socket kept.
The re-execed helper runs file_sync_service() before normal adbd/USB startup.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

MARKER = "J720F_ADB_SYNC_WORKER"
TARGET_CONTEXT = "u:r:recovery:s0"
ENV_NAME = "J720F_ADB_SYNC_FD"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def patch_services(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("services.cpp is already J720F sync-worker patched")

    include_anchor = '#include <cutils/sockets.h>\n'
    include_replacement = '''#include <cutils/sockets.h>\n\n#if !ADB_HOST\n#include <fcntl.h>\n#include <selinux/selinux.h>\n#include <signal.h>\n#include <sys/wait.h>\n#endif\n'''
    text = replace_once(text, include_anchor, include_replacement, "services device includes")

    insertion_anchor_re = re.compile(
        r'(?P<prefix>\n#endif\s*//\s*!ADB_HOST\s*\n\s*\n)(?P<create>static int create_service_thread)',
        re.MULTILINE,
    )
    matches = list(insertion_anchor_re.finditer(text))
    if len(matches) != 1:
        raise RuntimeError(
            "sync worker insertion: expected one !ADB_HOST boundary before create_service_thread, "
            f"found {len(matches)}"
        )

    helper = r'''// J720F_ADB_SYNC_WORKER: keep the long-lived USB daemon in u:r:adbd:s0,
// but execute legacy file_sync_service in a short-lived recovery-domain process.
// setexeccon is armed on this service thread before fork and cleared immediately
// in the parent. The child performs only fd setup and execve before re-entering
// normal libc/C++ code in adb/daemon/main.cpp.
static void j720f_recovery_sync_service(int fd, void*) {
    static constexpr char kRecoveryContext[] = "u:r:recovery:s0";
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 4 || max_fd > 32768) {
        max_fd = 1024;
    }

    errno = 0;
    if (setexeccon(kRecoveryContext) < 0) {
        D("J720F_ADB_SYNC_WORKER setexeccon failed: %s", strerror(errno));
        adb_close(fd);
        return;
    }

    errno = 0;
    const pid_t pid = fork();
    const int fork_errno = errno;

    if (pid != 0) {
        errno = 0;
        if (setexeccon(nullptr) < 0) {
            const int clear_errno = errno;
            (void)clear_errno;  // D() may compile out in non-tracing builds.
            if (pid > 0) {
                kill(pid, SIGKILL);
            }
            D("J720F_ADB_SYNC_WORKER parent clear setexeccon failed: %s",
              strerror(clear_errno));
            adb_close(fd);
            if (pid > 0) {
                while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
                }
            }
            return;
        }
    }
    errno = fork_errno;

    if (pid < 0) {
        D("J720F_ADB_SYNC_WORKER fork failed: %s", strerror(errno));
        adb_close(fd);
        return;
    }

    if (pid == 0) {
        static constexpr int kSyncFd = 3;
        if (fd != kSyncFd && dup2(fd, kSyncFd) < 0) {
            _exit(126);
        }
        if (fcntl(kSyncFd, F_SETFD, 0) < 0) {
            _exit(126);
        }
        for (int close_fd = 4; close_fd < max_fd; ++close_fd) {
            (void)adb_close(close_fd);
        }

        char arg0[] = "/sbin/adbd";
        char* const argv[] = {arg0, nullptr};
        char env_path[] = "PATH=/sbin:/system/bin";
        char env_ld[] = "LD_LIBRARY_PATH=/sbin";
        char env_shell[] = "SHELL=/sbin/sh";
        char env_android_root[] = "ANDROID_ROOT=/system";
        char env_android_data[] = "ANDROID_DATA=/data";
        char env_external_storage[] = "EXTERNAL_STORAGE=/sdcard";
        char env_tmpdir[] = "TMPDIR=/tmp";
        char env_sync_fd[] = "J720F_ADB_SYNC_FD=3";
        char* const envp[] = {
            env_path,
            env_ld,
            env_shell,
            env_android_root,
            env_android_data,
            env_external_storage,
            env_tmpdir,
            env_sync_fd,
            nullptr,
        };
        execve("/sbin/adbd", argv, envp);
        _exit(127);
    }

    adb_close(fd);
    while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
    }
}

'''
    m = matches[0]
    text = text[: m.start()] + "\n" + helper + m.group("prefix") + m.group("create") + text[m.end() :]

    # Preserve donor versions that special-case sync socket buffer sizing by
    # function pointer. Our wrapper is still the sync service for that purpose.
    buffer_anchor = 'if (func == &file_sync_service) {'
    if text.count(buffer_anchor) == 1:
        text = text.replace(
            buffer_anchor,
            'if (func == &file_sync_service || func == &j720f_recovery_sync_service) {',
            1,
        )

    sync_anchor = 'ret = create_service_thread(file_sync_service, NULL);'
    if text.count(sync_anchor) != 1:
        # Some nearby donor revisions name service threads. Fail closed but support that exact shape too.
        named_anchor = 'ret = create_service_thread("sync", file_sync_service, nullptr);'
        if text.count(named_anchor) != 1:
            raise RuntimeError("sync service dispatch: unsupported create_service_thread form")
        text = text.replace(
            named_anchor,
            'ret = create_service_thread("sync", j720f_recovery_sync_service, nullptr);',
            1,
        )
    else:
        text = text.replace(
            sync_anchor,
            'ret = create_service_thread(j720f_recovery_sync_service, NULL);',
            1,
        )

    required = (
        MARKER,
        'setexeccon(kRecoveryContext)',
        'setexeccon(nullptr)',
        'execve("/sbin/adbd", argv, envp)',
        'J720F_ADB_SYNC_FD=3',
        'j720f_recovery_sync_service',
    )
    for item in required:
        if item not in text:
            raise RuntimeError(f"patched services.cpp missing required marker: {item}")
    return text


def patch_main(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("daemon/main.cpp is already J720F sync-worker patched")

    include_anchor = '#include "adb_utils.h"\n'
    include_replacement = '#include "adb_utils.h"\n#include "file_sync_service.h"\n#include <selinux/selinux.h>\n'
    text = replace_once(text, include_anchor, include_replacement, "daemon sync includes")

    main_anchor = '''#if !ADB_HOST
int recovery_mode = 0;
#endif

int main(int argc, char** argv) {
'''
    helper = r'''#if !ADB_HOST
int recovery_mode = 0;

// J720F_ADB_SYNC_WORKER: a self-execed /sbin/adbd with J720F_ADB_SYNC_FD set
// is a single-purpose file-sync helper. It must never enter adbd_main()/USB.
static int j720f_maybe_run_recovery_sync_worker() {
    const char* fd_env = getenv("J720F_ADB_SYNC_FD");
    if (fd_env == nullptr) {
        return -1;
    }

    errno = 0;
    char* end = nullptr;
    const long parsed_fd = strtol(fd_env, &end, 10);
    if (errno != 0 || end == fd_env || *end != '\0' || parsed_fd != 3) {
        fprintf(stderr, "J720F_ADB_SYNC_WORKER invalid fd '%s'\n", fd_env);
        return 125;
    }

    char* context = nullptr;
    errno = 0;
    const int context_result = getcon(&context);
    const int context_errno = errno;
    const bool root_ok = getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0;
    const bool context_ok = context_result == 0 && context != nullptr &&
                            strcmp(context, "u:r:recovery:s0") == 0;
    fprintf(stderr,
            "J720F_ADB_SYNC_WORKER phase=entry fd=%ld uid=%d euid=%d gid=%d egid=%d "
            "context=%s context_errno=%d\n",
            parsed_fd, static_cast<int>(getuid()), static_cast<int>(geteuid()),
            static_cast<int>(getgid()), static_cast<int>(getegid()),
            context != nullptr ? context : "<unavailable>", context_errno);
    if (context != nullptr) {
        freecon(context);
    }
    if (!root_ok || !context_ok) {
        fprintf(stderr, "J720F_ADB_SYNC_WORKER refused non-root/non-recovery helper\n");
        return 126;
    }

    file_sync_service(static_cast<int>(parsed_fd), nullptr);
    return 0;
}
#endif

int main(int argc, char** argv) {
#if !ADB_HOST
    const int j720f_sync_worker_result = j720f_maybe_run_recovery_sync_worker();
    if (j720f_sync_worker_result >= 0) {
        return j720f_sync_worker_result;
    }
#endif
'''
    text = replace_once(text, main_anchor, helper, "daemon early sync-worker dispatch")

    required = (
        MARKER,
        'getenv("J720F_ADB_SYNC_FD")',
        'strcmp(context, "u:r:recovery:s0")',
        'file_sync_service(static_cast<int>(parsed_fd), nullptr)',
        'j720f_maybe_run_recovery_sync_worker()',
    )
    for item in required:
        if item not in text:
            raise RuntimeError(f"patched daemon/main.cpp missing required marker: {item}")
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system-core", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    root = args.system_core.resolve()
    services_path = root / "adb/services.cpp"
    main_path = root / "adb/daemon/main.cpp"
    services_before = services_path.read_text()
    main_before = main_path.read_text()
    services_after = patch_services(services_before)
    main_after = patch_main(main_before)
    services_path.write_text(services_after)
    main_path.write_text(main_after)

    report = {
        "sources": ["adb/services.cpp", "adb/daemon/main.cpp"],
        "services_sha256_before": sha256(services_before),
        "services_sha256_after": sha256(services_after),
        "main_sha256_before": sha256(main_before),
        "main_sha256_after": sha256(main_after),
        "required_marker": MARKER,
        "target_context": TARGET_CONTEXT,
        "worker_fd_environment": ENV_NAME,
        "architecture": "service-thread setexeccon -> fork -> self-exec /sbin/adbd -> file_sync_service",
        "parent_adbd_stays_adbd": True,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
