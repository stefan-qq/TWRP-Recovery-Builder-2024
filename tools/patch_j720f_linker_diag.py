#!/usr/bin/env python3
"""Instrument Android 7.1 bionic linker for the J720F recovery shell failure.

The adbd shell child is root immediately before exec(/sbin/sh), yet the dynamic
linker later reports uid/gid 2000 and cannot open /sbin/libc.so. Instrument the
exact donor linker at multiple initialization phases to locate the credential
transition and record the kernel-provided auxv credentials. Keep the existing
AT_SECURE/LD_LIBRARY_PATH/rootfs libc probe. No linker behavior is changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_LINKER_DIAG"
CRED_MARKER = "J720F_LINKER_CRED"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def patch_linker(text: str) -> str:
    if MARKER in text or CRED_MARKER in text:
        raise RuntimeError("linker.cpp is already J720F linker-diagnostic patched")

    helper_anchor = '''extern "C" int __system_properties_init(void);\n\nstatic const char* get_executable_path() {\n'''
    helper_replacement = r'''extern "C" int __system_properties_init(void);

static bool j720f_is_recovery_shell(KernelArgumentBlock& args) {
  return args.argv != nullptr && args.argv[0] != nullptr &&
         (strcmp(args.argv[0], "/sbin/sh") == 0 ||
          strcmp(args.argv[0], "/sbin/busybox") == 0);
}

static void j720f_linker_cred_diag(KernelArgumentBlock& args, const char* phase) {
  if (!j720f_is_recovery_shell(args)) return;

  struct stat exe_st;
  errno = 0;
  const int exe_stat = TEMP_FAILURE_RETRY(stat("/proc/self/exe", &exe_st));
  const int exe_errno = exe_stat == 0 ? 0 : errno;

  __libc_format_fd(
      STDERR_FILENO,
      "J720F_LINKER_CRED phase=%s uid=%d euid=%d gid=%d egid=%d "
      "aux_uid=%lu aux_euid=%lu aux_gid=%lu aux_egid=%lu aux_secure=%lu "
      "exe_stat=%d exe_errno=%d exe_mode=%04o exe_uid=%d exe_gid=%d\n",
      phase, static_cast<int>(getuid()), static_cast<int>(geteuid()),
      static_cast<int>(getgid()), static_cast<int>(getegid()),
      args.getauxval(AT_UID), args.getauxval(AT_EUID),
      args.getauxval(AT_GID), args.getauxval(AT_EGID),
      args.getauxval(AT_SECURE), exe_stat, exe_errno,
      exe_stat == 0 ? static_cast<unsigned int>(exe_st.st_mode & 07777) : 0,
      exe_stat == 0 ? static_cast<int>(exe_st.st_uid) : -1,
      exe_stat == 0 ? static_cast<int>(exe_st.st_gid) : -1);
}

static const char* get_executable_path() {
'''
    text = replace_once(text, helper_anchor, helper_replacement, "credential helper insertion")

    post_anchor = '''static ElfW(Addr) __linker_init_post_relocation(KernelArgumentBlock& args, ElfW(Addr) linker_base) {\n#if TIMING\n  struct timeval t0, t1;\n  gettimeofday(&t0, 0);\n#endif\n\n  // Sanitize the environment.\n  __libc_init_AT_SECURE(args);\n\n  // Initialize system properties\n  __system_properties_init(); // may use 'environ'\n\n  debuggerd_init();\n'''
    post_replacement = '''static ElfW(Addr) __linker_init_post_relocation(KernelArgumentBlock& args, ElfW(Addr) linker_base) {\n#if TIMING\n  struct timeval t0, t1;\n  gettimeofday(&t0, 0);\n#endif\n\n  j720f_linker_cred_diag(args, "post_relocation_entry");\n\n  // Sanitize the environment.\n  __libc_init_AT_SECURE(args);\n  j720f_linker_cred_diag(args, "after_at_secure");\n\n  // Initialize system properties\n  __system_properties_init(); // may use 'environ'\n  j720f_linker_cred_diag(args, "after_properties");\n\n  debuggerd_init();\n  j720f_linker_cred_diag(args, "after_debuggerd");\n'''
    text = replace_once(text, post_anchor, post_replacement, "post-relocation credential stages")

    main_thread_anchor = '''  // Initialize the main thread (including TLS, so system calls really work).\n  __libc_init_main_thread(args);\n\n  // We didn't protect the linker's RELRO pages in link_image because we\n'''
    main_thread_replacement = '''  // Initialize the main thread (including TLS, so system calls really work).\n  __libc_init_main_thread(args);\n  j720f_linker_cred_diag(args, "after_main_thread");\n\n  // We didn't protect the linker's RELRO pages in link_image because we\n'''
    text = replace_once(text, main_thread_anchor, main_thread_replacement, "main-thread credential stage")

    globals_anchor = '''  // Initialize the linker's static libc's globals\n  __libc_init_globals(args);\n\n  // Initialize the linker's own global variables\n  linker_so.call_constructors();\n'''
    globals_replacement = '''  // Initialize the linker's static libc's globals\n  __libc_init_globals(args);\n  j720f_linker_cred_diag(args, "after_libc_globals");\n\n  // Initialize the linker's own global variables\n  linker_so.call_constructors();\n  j720f_linker_cred_diag(args, "after_linker_constructors");\n'''
    text = replace_once(text, globals_anchor, globals_replacement, "linker-global credential stages")

    before_post_anchor = '''  // We have successfully fixed our own relocations. It's safe to run\n  // the main part of the linker now.\n  args.abort_message_ptr = &g_abort_message;\n  ElfW(Addr) start_address = __linker_init_post_relocation(args, linker_addr);\n'''
    before_post_replacement = '''  // We have successfully fixed our own relocations. It's safe to run\n  // the main part of the linker now.\n  args.abort_message_ptr = &g_abort_message;\n  j720f_linker_cred_diag(args, "before_post_relocation");\n  ElfW(Addr) start_address = __linker_init_post_relocation(args, linker_addr);\n'''
    text = replace_once(text, before_post_anchor, before_post_replacement, "pre-post-relocation credential stage")

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
  if (j720f_is_recovery_shell(args)) {
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
        "credential_marker": CRED_MARKER,
        "behavior_change": False,
        "diagnostic": "linker64 credential phases plus AT_SECURE/LD_LIBRARY_PATH/rootfs libc access",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
