#!/usr/bin/env python3
"""Instrument Android 7.1 bionic linker for the J720F recovery shell failure.

The recovery adbd child now reaches exec(/sbin/sh), but linker64 reports
"libc.so not found" even though /sbin/libc.so exists and adbd inherited
LD_LIBRARY_PATH=/sbin. Kernel AVC logging is silent.

Patch the donor bionic linker only for a diagnostic build. For /sbin/sh or
/sbin/busybox, print one compact stderr line after AT_SECURE environment
sanitization and from inside the new shell process. The line records the actual
AT_SECURE value seen by linker64, the post-sanitization LD_LIBRARY_PATH, the
SELinux context, direct /sbin/libc.so open/mmap results, and realpath(/sbin).
No linker search behavior is changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_LINKER_DIAG"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def patch_linker(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("linker.cpp is already J720F linker-diagnostic patched")

    anchor = '''  const char* ldpath_env = nullptr;\n  const char* ldpreload_env = nullptr;\n  const char* ldshim_libs_env = nullptr;\n  if (!getauxval(AT_SECURE)) {\n'''
    if anchor not in text:
        raise RuntimeError("linker.cpp missing Android 7.1 LD_LIBRARY_PATH anchor")

    replacement = r'''  const char* ldpath_env = nullptr;
  const char* ldpreload_env = nullptr;
  const char* ldshim_libs_env = nullptr;

  // J720F recovery-shell linker diagnostic. Do not change linker search
  // behavior: only report what the newly exec'd /sbin/sh process actually
  // sees after bionic's AT_SECURE environment sanitization.
  const unsigned long j720f_at_secure = getauxval(AT_SECURE);
  if (args.argv != nullptr && args.argv[0] != nullptr &&
      (strcmp(args.argv[0], "/sbin/sh") == 0 ||
       strcmp(args.argv[0], "/sbin/busybox") == 0)) {
    const char* j720f_ld_library_path = getenv("LD_LIBRARY_PATH");

    int libc_errno = 0;
    int libc_fd = TEMP_FAILURE_RETRY(open("/sbin/libc.so", O_RDONLY | O_CLOEXEC));
    if (libc_fd < 0) libc_errno = errno;

    int mmap_ok = 0;
    int mmap_errno = 0;
    if (libc_fd >= 0) {
      errno = 0;
      void* mapping = mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, libc_fd, 0);
      if (mapping == MAP_FAILED) {
        mmap_errno = errno;
      } else {
        mmap_ok = 1;
        munmap(mapping, 4096);
      }
    }

    char context[128];
    strcpy(context, "<unreadable>");
    int context_errno = 0;
    int context_fd = TEMP_FAILURE_RETRY(open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC));
    if (context_fd < 0) {
      context_errno = errno;
    } else {
      ssize_t context_count = TEMP_FAILURE_RETRY(read(context_fd, context, sizeof(context) - 1));
      if (context_count < 0) {
        context_errno = errno;
        strcpy(context, "<read-failed>");
      } else {
        while (context_count > 0 &&
               (context[context_count - 1] == '\n' || context[context_count - 1] == '\r')) {
          --context_count;
        }
        context[context_count] = '\0';
      }
      close(context_fd);
    }

    char resolved_sbin[PATH_MAX];
    errno = 0;
    char* realpath_result = realpath("/sbin", resolved_sbin);
    const int realpath_errno = realpath_result == nullptr ? errno : 0;

    __libc_format_fd(
        STDERR_FILENO,
        "J720F_LINKER_DIAG argv0=%s uid=%d gid=%d at_secure=%lu ld_library_path=%s "
        "context=%s context_errno=%d libc_open=%d libc_errno=%d "
        "libc_mmap_exec=%d mmap_errno=%d realpath_sbin=%s realpath_errno=%d\n",
        args.argv[0], static_cast<int>(getuid()), static_cast<int>(getgid()),
        j720f_at_secure,
        j720f_ld_library_path == nullptr ? "<null>" : j720f_ld_library_path,
        context, context_errno, libc_fd >= 0 ? 1 : 0, libc_errno,
        mmap_ok, mmap_errno,
        realpath_result == nullptr ? "<failed>" : resolved_sbin, realpath_errno);

    if (libc_fd >= 0) close(libc_fd);
  }

  if (!j720f_at_secure) {
'''
    return replace_once(text, anchor, replacement, "linker diagnostic insertion")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bionic", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    root = args.bionic.resolve()
    path = root / "linker/linker.cpp"
    if not path.is_file():
        raise SystemExit(f"missing source file: {path}")

    original = path.read_text()
    patched = patch_linker(original)
    path.write_text(patched)

    report = {
        "source": str(path.relative_to(root)),
        "sha256_before": sha256(original),
        "sha256_after": sha256(patched),
        "required_marker": MARKER,
        "behavior_change": False,
        "diagnostic": "linker64 AT_SECURE/LD_LIBRARY_PATH/rootfs libc access",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
