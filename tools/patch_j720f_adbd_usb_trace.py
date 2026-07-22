#!/usr/bin/env python3
"""Instrument Android 7.1 adbd for decisive SM-J720F FunctionFS tracing.

The patch is intentionally applied at build time to the synced system/core tree.
It writes two fixed files in recovery tmpfs:

* /tmp/J720F_ADBD_USB_TRACE.txt: direct syscall/result/errno checkpoints.
* /tmp/J720F_ADBD_TRACE.txt: native ADB_TRACE output.

The script uses strict anchors and refuses unknown/already-patched source so a
manifest update cannot silently produce a different diagnostic binary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

USB_MARKER = "J720F_USB_DIAG"
USB_TRACE_PATH = "/tmp/J720F_ADBD_USB_TRACE.txt"
ADB_TRACE_PATH = "/tmp/J720F_ADBD_TRACE.txt"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def git_output(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True
    ).strip()


def git_remote_url(root: Path) -> str:
    remotes = git_output(root, "remote").splitlines()
    if not remotes:
        return "unknown"
    return git_output(root, "remote", "get-url", remotes[0])


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def replace_regex_once(
    text: str, pattern: str, replacement: str, label: str, flags: int = 0
) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise RuntimeError(f"{label}: expected one regex anchor, found {count}")
    return updated


def function_span(text: str, signature_pattern: str, label: str) -> tuple[int, int]:
    matches = list(re.finditer(signature_pattern, text, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError(f"{label}: expected one function signature, found {len(matches)}")
    start = matches[0].start()
    brace = text.find("{", matches[0].end())
    if brace < 0:
        raise RuntimeError(f"{label}: opening brace not found")
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return start, index + 1
    raise RuntimeError(f"{label}: closing brace not found")


def patch_function(
    text: str,
    signature_pattern: str,
    label: str,
    transform,
) -> str:
    start, end = function_span(text, signature_pattern, label)
    original = text[start:end]
    updated = transform(original)
    if updated == original:
        raise RuntimeError(f"{label}: transform made no change")
    return text[:start] + updated + text[end:]


def patch_usb_source(text: str) -> str:
    if USB_MARKER in text or USB_TRACE_PATH in text:
        raise RuntimeError("usb_linux_client.cpp is already instrumented")
    for required in (
        "static bool init_functionfs",
        "static void usb_ffs_open_thread",
        "static void usb_ffs_init",
        "void usb_init",
        "USB_FFS_ADB_EP0",
        'property_set("sys.usb.ffs.ready", "1")',
    ):
        if required not in text:
            raise RuntimeError(f"usb_linux_client.cpp missing required anchor: {required}")

    if "#include <stdarg.h>" not in text:
        text = replace_once(
            text,
            "#include <stdio.h>\n",
            "#include <stdio.h>\n#include <stdarg.h>\n",
            "stdarg include",
        )

    helper = r'''
// J720F direct FunctionFS diagnostic. This branch is not a release build.
// init pre-creates the fixed tmpfs file before adbd starts, so this logger
// does not depend on /data, logd, recovery-domain /proc access, or host USB.
static void j720f_usb_diag(const char* format, ...) {
    const int saved_errno = errno;
    int fd = unix_open("/tmp/J720F_ADBD_USB_TRACE.txt", O_WRONLY | O_APPEND);
    if (fd < 0) {
        errno = saved_errno;
        return;
    }
    close_on_exec(fd);

    char line[1024];
    int prefix = snprintf(line, sizeof(line),
                          "J720F_USB_DIAG pid=%d uid=%d gid=%d ",
                          getpid(), getuid(), getgid());
    if (prefix < 0) prefix = 0;
    if (prefix >= static_cast<int>(sizeof(line))) {
        prefix = static_cast<int>(sizeof(line)) - 1;
    }

    va_list ap;
    va_start(ap, format);
    int body = vsnprintf(line + prefix, sizeof(line) - prefix, format, ap);
    va_end(ap);
    if (body < 0) body = 0;

    size_t total = static_cast<size_t>(prefix);
    size_t remaining = sizeof(line) - total;
    if (remaining > 1) {
        size_t used = static_cast<size_t>(body);
        if (used >= remaining) used = remaining - 1;
        total += used;
    }
    if (total == 0 || line[total - 1] != '\n') {
        if (total < sizeof(line) - 1) line[total++] = '\n';
    }
    unix_write(fd, line, total);
    unix_close(fd);
    errno = saved_errno;
}

static void j720f_usb_diag_identity() {
    const int saved_errno = errno;
    char context[128] = "unavailable";
    int context_errno = 0;
    int fd = unix_open("/proc/self/attr/current", O_RDONLY);
    if (fd >= 0) {
        int count = unix_read(fd, context, sizeof(context) - 1);
        if (count >= 0) {
            context[count] = '\0';
            while (count > 0 &&
                   (context[count - 1] == '\n' || context[count - 1] == '\r')) {
                context[--count] = '\0';
            }
        } else {
            context_errno = errno;
            strcpy(context, "read-failed");
        }
        unix_close(fd);
    } else {
        context_errno = errno;
        strcpy(context, "open-failed");
    }
    j720f_usb_diag("event=identity context=%s context_errno=%d (%s)",
                    context, context_errno,
                    context_errno == 0 ? "ok" : strerror(context_errno));
    errno = saved_errno;
}

'''
    text = replace_once(
        text,
        "static bool init_functionfs",
        helper + "static bool init_functionfs",
        "direct trace helper insertion",
    )

    def patch_init_functionfs(fn: str) -> str:
        fn = replace_regex_once(
            fn,
            r"(static bool init_functionfs\s*\([^)]*\)\s*\{)",
            r'''\1
    j720f_usb_diag("event=init_functionfs_enter control=%d bulk_out=%d bulk_in=%d",
                    h->control, h->bulk_out, h->bulk_in);''',
            "init_functionfs entry",
        )
        fn = replace_once(
            fn,
            "    if (h->control < 0) { // might have already done this before",
            '''    j720f_usb_diag("event=descriptor_layout v2_bytes=%zu v1_bytes=%zu strings_bytes=%zu v2_flags=0x%x",
                    sizeof(v2_descriptor), sizeof(v1_descriptor), sizeof(strings),
                    static_cast<unsigned int>(v2_descriptor.header.flags));
    if (h->control < 0) { // might have already done this before''',
            "descriptor layout checkpoint",
        )
        fn = replace_regex_once(
            fn,
            r"(?m)^(\s*)h->control\s*=\s*adb_open\(USB_FFS_ADB_EP0,\s*O_RDWR\);\s*$",
            r'''\1errno = 0;
\1h->control = adb_open(USB_FFS_ADB_EP0, O_RDWR);
\1{
\1    const int operation_errno = errno;
\1    j720f_usb_diag("event=ep0_open path=%s fd=%d errno=%d (%s)",
\1                    USB_FFS_ADB_EP0, h->control, operation_errno,
\1                    operation_errno == 0 ? "ok" : strerror(operation_errno));
\1}''',
            "ep0 open checkpoint",
        )
        fn = replace_regex_once(
            fn,
            r"(?m)^(\s*)ret\s*=\s*adb_write\(h->control,\s*&v2_descriptor,\s*sizeof\(v2_descriptor\)\);\s*$",
            r'''\1errno = 0;
\1ret = adb_write(h->control, &v2_descriptor, sizeof(v2_descriptor));
\1{
\1    const int operation_errno = errno;
\1    j720f_usb_diag("event=v2_descriptor_write fd=%d ret=%zd expected=%zu errno=%d (%s)",
\1                    h->control, ret, sizeof(v2_descriptor), operation_errno,
\1                    operation_errno == 0 ? "ok" : strerror(operation_errno));
\1}''',
            "v2 descriptor checkpoint",
        )
        fn = replace_regex_once(
            fn,
            r"(?m)^(\s*)ret\s*=\s*adb_write\(h->control,\s*&v1_descriptor,\s*sizeof\(v1_descriptor\)\);\s*$",
            r'''\1errno = 0;
\1ret = adb_write(h->control, &v1_descriptor, sizeof(v1_descriptor));
\1{
\1    const int operation_errno = errno;
\1    j720f_usb_diag("event=v1_descriptor_write fd=%d ret=%zd expected=%zu errno=%d (%s)",
\1                    h->control, ret, sizeof(v1_descriptor), operation_errno,
\1                    operation_errno == 0 ? "ok" : strerror(operation_errno));
\1}''',
            "v1 descriptor checkpoint",
        )
        fn = replace_regex_once(
            fn,
            r"(?m)^(\s*)ret\s*=\s*adb_write\(h->control,\s*&strings,\s*sizeof\(strings\)\);\s*$",
            r'''\1errno = 0;
\1ret = adb_write(h->control, &strings, sizeof(strings));
\1{
\1    const int operation_errno = errno;
\1    j720f_usb_diag("event=strings_write fd=%d ret=%zd expected=%zu errno=%d (%s)",
\1                    h->control, ret, sizeof(strings), operation_errno,
\1                    operation_errno == 0 ? "ok" : strerror(operation_errno));
\1}''',
            "strings checkpoint",
        )
        fn = replace_regex_once(
            fn,
            r"(?m)^(\s*)h->bulk_out\s*=\s*adb_open\(USB_FFS_ADB_OUT,\s*O_RDWR\);\s*$",
            r'''\1errno = 0;
\1h->bulk_out = adb_open(USB_FFS_ADB_OUT, O_RDWR);
\1{
\1    const int operation_errno = errno;
\1    j720f_usb_diag("event=ep1_bulk_out_open path=%s fd=%d errno=%d (%s)",
\1                    USB_FFS_ADB_OUT, h->bulk_out, operation_errno,
\1                    operation_errno == 0 ? "ok" : strerror(operation_errno));
\1}''',
            "bulk-out checkpoint",
        )
        fn = replace_regex_once(
            fn,
            r"(?m)^(\s*)h->bulk_in\s*=\s*adb_open\(USB_FFS_ADB_IN,\s*O_RDWR\);\s*$",
            r'''\1errno = 0;
\1h->bulk_in = adb_open(USB_FFS_ADB_IN, O_RDWR);
\1{
\1    const int operation_errno = errno;
\1    j720f_usb_diag("event=ep2_bulk_in_open path=%s fd=%d errno=%d (%s)",
\1                    USB_FFS_ADB_IN, h->bulk_in, operation_errno,
\1                    operation_errno == 0 ? "ok" : strerror(operation_errno));
\1}''',
            "bulk-in checkpoint",
        )
        fn = replace_regex_once(
            fn,
            r"(?m)^    return true;\n(?:\n)?err:",
            '''    j720f_usb_diag("event=init_functionfs_success control=%d bulk_out=%d bulk_in=%d",
                    h->control, h->bulk_out, h->bulk_in);
    return true;

err:
    j720f_usb_diag("event=init_functionfs_error control=%d bulk_out=%d bulk_in=%d errno=%d (%s)",
                    h->control, h->bulk_out, h->bulk_in, errno, strerror(errno));''',
            "init_functionfs result checkpoints",
        )
        return fn

    text = patch_function(
        text,
        r"^static bool init_functionfs\s*\(",
        "init_functionfs",
        patch_init_functionfs,
    )

    def patch_open_thread(fn: str) -> str:
        fn = replace_once(
            fn,
            '    adb_thread_setname("usb ffs open");\n',
            '    adb_thread_setname("usb ffs open");\n'
            '    unsigned int j720f_attempt = 0;\n'
            '    j720f_usb_diag("event=usb_ffs_open_thread_start");\n',
            "USB open thread entry",
        )
        fn = replace_once(
            fn,
            "            if (init_functionfs(usb)) {\n                break;\n            }\n            adb_sleep_ms(1000);",
            '''            ++j720f_attempt;
            j720f_usb_diag("event=init_functionfs_attempt attempt=%u", j720f_attempt);
            if (init_functionfs(usb)) {
                j720f_usb_diag("event=init_functionfs_attempt_success attempt=%u", j720f_attempt);
                break;
            }
            j720f_usb_diag("event=init_functionfs_attempt_failed attempt=%u", j720f_attempt);
            adb_sleep_ms(1000);''',
            "FunctionFS retry loop",
        )
        fn = replace_once(
            fn,
            '        property_set("sys.usb.ffs.ready", "1");',
            '''        errno = 0;
        const int property_result = property_set("sys.usb.ffs.ready", "1");
        const int property_errno = errno;
        j720f_usb_diag("event=ffs_ready_property_set result=%d errno=%d (%s) value=%s",
                        property_result, property_errno,
                        property_errno == 0 ? "ok" : strerror(property_errno),
                        property_result == 0 ? "1" : "unchanged");''',
            "ffs.ready property checkpoint",
        )
        fn = replace_once(
            fn,
            "        register_usb_transport(usb, 0, 0, 1);",
            '''        j720f_usb_diag("event=register_usb_transport control=%d bulk_out=%d bulk_in=%d",
                        usb->control, usb->bulk_out, usb->bulk_in);
        register_usb_transport(usb, 0, 0, 1);''',
            "transport registration checkpoint",
        )
        return fn

    text = patch_function(
        text,
        r"^static void usb_ffs_open_thread\s*\(",
        "usb_ffs_open_thread",
        patch_open_thread,
    )

    def patch_ffs_init(fn: str) -> str:
        fn = replace_once(
            fn,
            '    D("[ usb_init - using FunctionFS ]");',
            '''    j720f_usb_diag_identity();
    j720f_usb_diag("event=usb_ffs_init_enter ep0=%s ep1=%s ep2=%s",
                    USB_FFS_ADB_EP0, USB_FFS_ADB_OUT, USB_FFS_ADB_IN);
    D("[ usb_init - using FunctionFS ]");''',
            "usb_ffs_init entry",
        )
        fn = replace_once(
            fn,
            "    if (!adb_thread_create(usb_ffs_open_thread, h)) {",
            '''    j720f_usb_diag("event=usb_ffs_thread_create_begin control=%d bulk_out=%d bulk_in=%d",
                    h->control, h->bulk_out, h->bulk_in);
    if (!adb_thread_create(usb_ffs_open_thread, h)) {''',
            "USB thread create checkpoint",
        )
        return fn

    text = patch_function(
        text,
        r"^static void usb_ffs_init\s*\(",
        "usb_ffs_init",
        patch_ffs_init,
    )

    def patch_usb_init(fn: str) -> str:
        fn = replace_regex_once(
            fn,
            r"(void usb_init\s*\(\s*\)\s*\{)",
            r'''\1
    errno = 0;
    const int ep0_access = access(USB_FFS_ADB_EP0, F_OK);
    const int ep0_errno = errno;
    j720f_usb_diag("event=usb_init ep0=%s access=%d errno=%d (%s)",
                    USB_FFS_ADB_EP0, ep0_access, ep0_errno,
                    ep0_errno == 0 ? "ok" : strerror(ep0_errno));''',
            "usb_init entry",
        )
        return fn

    text = patch_function(text, r"^void usb_init\s*\(", "usb_init", patch_usb_init)

    required_markers = (
        "event=identity",
        "event=ep0_open",
        "event=v2_descriptor_write",
        "event=v1_descriptor_write",
        "event=strings_write",
        "event=ep1_bulk_out_open",
        "event=ep2_bulk_in_open",
        "event=ffs_ready_property_set",
        "event=register_usb_transport",
    )
    for marker in required_markers:
        if marker not in text:
            raise RuntimeError(f"patched USB source missing marker: {marker}")
    return text


def patch_adb_trace_source(text: str) -> str:
    if ADB_TRACE_PATH in text:
        raise RuntimeError("adb_trace.cpp is already redirected to recovery tmpfs")
    if "/data/adb/adb-" not in text:
        raise RuntimeError("adb_trace.cpp does not contain the expected /data trace path")

    start, end = function_span(
        text,
        r"^static std::string get_log_file_name\s*\(",
        "get_log_file_name",
    )
    replacement = '''static std::string get_log_file_name() {
    // J720F direct-trace diagnostic: /data is intentionally not involved.
    return "/tmp/J720F_ADBD_TRACE.txt";
}'''
    text = text[:start] + replacement + text[end:]
    if "/data/adb/adb-" in text:
        raise RuntimeError("old /data ADB trace path remains after patch")
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system-core", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    root = args.system_core.resolve()
    usb_path = root / "adb/usb_linux_client.cpp"
    trace_path = root / "adb/adb_trace.cpp"
    for path in (usb_path, trace_path):
        if not path.is_file():
            raise SystemExit(f"missing source file: {path}")

    commit = git_output(root, "rev-parse", "HEAD")
    remote = git_remote_url(root)

    original_usb = usb_path.read_text()
    original_trace = trace_path.read_text()
    patched_usb = patch_usb_source(original_usb)
    patched_trace = patch_adb_trace_source(original_trace)

    usb_path.write_text(patched_usb)
    trace_path.write_text(patched_trace)

    report = {
        "system_core_repository": remote,
        "system_core_commit": commit,
        "usb_source": str(usb_path.relative_to(root)),
        "usb_sha256_before": sha256(original_usb),
        "usb_sha256_after": sha256(patched_usb),
        "adb_trace_source": str(trace_path.relative_to(root)),
        "adb_trace_sha256_before": sha256(original_trace),
        "adb_trace_sha256_after": sha256(patched_trace),
        "direct_trace_path": USB_TRACE_PATH,
        "native_trace_path": ADB_TRACE_PATH,
        "required_events": [
            "identity",
            "usb_init",
            "usb_ffs_init_enter",
            "init_functionfs_attempt",
            "ep0_open",
            "v2_descriptor_write",
            "v1_descriptor_write",
            "strings_write",
            "ep1_bulk_out_open",
            "ep2_bulk_in_open",
            "ffs_ready_property_set",
            "register_usb_transport",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
