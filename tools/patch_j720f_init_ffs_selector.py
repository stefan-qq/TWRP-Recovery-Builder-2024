#!/usr/bin/env python3
"""Apply the Samsung CUL1 FunctionFS selector fallback in Android 7.1 init."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MARKER = "J720F_FFS_SELECTOR"
FUNCTIONS_PATH = "/sys/class/android_usb/android0/functions"
KERNEL_FUNCTION_NAME = "Function FS Gadget"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return text.replace(old, new, 1)


def patch_util(text: str) -> str:
    if MARKER in text or KERNEL_FUNCTION_NAME in text:
        raise RuntimeError("init/util.cpp is already J720F FunctionFS-selector patched")

    if "#include <unistd.h>\n" not in text:
        text = replace_once(
            text,
            "#include <errno.h>\n",
            "#include <errno.h>\n#include <unistd.h>\n",
            "unistd include insertion",
        )

    old_write = '''int write_file(const char* path, const char* content) {
    int fd = TEMP_FAILURE_RETRY(open(path, O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600));
    if (fd == -1) {
        NOTICE("write_file: Unable to open '%s': %s\\n", path, strerror(errno));
        return -1;
    }
    int result = android::base::WriteStringToFd(content, fd) ? 0 : -1;
    if (result == -1) {
        NOTICE("write_file: Unable to write to '%s': %s\\n", path, strerror(errno));
    }
    close(fd);
    return result;
}
'''

    new_write = r'''// J720F_FFS_SELECTOR: Samsung CONFIG_USB_CONFIGFS_UEVENT selects newly linked
// functions by the kernel usb_function->name. FunctionFS exposes the name
// "Function FS Gadget", while stock recovery asks android0/functions for "adb".
// If that successful stock-style write leaves the selector empty, retry once
// with the kernel-visible FunctionFS name before the normal ConfigFS UDC bind.
static const char* const kJ720fAndroidFunctionsPath =
        "/sys/class/android_usb/android0/functions";
static const char* const kJ720fFfsKernelFunctionName = "Function FS Gadget";

static bool j720f_file_has_nonspace(const char* path) {
    const int saved_errno = errno;
    int fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        errno = saved_errno;
        return false;
    }
    char value[256];
    const ssize_t count = TEMP_FAILURE_RETRY(read(fd, value, sizeof(value)));
    close(fd);
    if (count <= 0) {
        errno = saved_errno;
        return false;
    }
    for (ssize_t i = 0; i < count; ++i) {
        if (value[i] != ' ' && value[i] != '\t' && value[i] != '\r' && value[i] != '\n') {
            errno = saved_errno;
            return true;
        }
    }
    errno = saved_errno;
    return false;
}

static void j720f_select_ffs_if_needed() {
    const int saved_errno = errno;
    if (j720f_file_has_nonspace(kJ720fAndroidFunctionsPath)) {
        errno = saved_errno;
        return;
    }

    int fd = TEMP_FAILURE_RETRY(open(kJ720fAndroidFunctionsPath, O_WRONLY | O_CLOEXEC));
    if (fd >= 0) {
        const size_t expected = strlen(kJ720fFfsKernelFunctionName);
        const ssize_t written = TEMP_FAILURE_RETRY(
                write(fd, kJ720fFfsKernelFunctionName, expected));
        if (written != static_cast<ssize_t>(expected)) {
            NOTICE("J720F FunctionFS selector fallback failed: %s\n", strerror(errno));
        }
        close(fd);
    } else {
        NOTICE("J720F FunctionFS selector fallback open failed: %s\n", strerror(errno));
    }
    errno = saved_errno;
}

int write_file(const char* path, const char* content) {
    int fd = TEMP_FAILURE_RETRY(open(path, O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600));
    if (fd == -1) {
        NOTICE("write_file: Unable to open '%s': %s\n", path, strerror(errno));
        return -1;
    }
    int result = android::base::WriteStringToFd(content, fd) ? 0 : -1;
    if (result == -1) {
        NOTICE("write_file: Unable to write to '%s': %s\n", path, strerror(errno));
    }
    close(fd);

    const int final_errno = errno;
    if (result == 0 && !strcmp(path, kJ720fAndroidFunctionsPath) && !strcmp(content, "adb")) {
        j720f_select_ffs_if_needed();
    }
    errno = final_errno;
    return result;
}
'''
    return replace_once(text, old_write, new_write, "write_file FunctionFS selector")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system-core", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    root = args.system_core.resolve()
    path = root / "init/util.cpp"
    if not path.is_file():
        raise SystemExit(f"missing source file: {path}")

    original = path.read_text()
    patched = patch_util(original)
    path.write_text(patched)

    report = {
        "source": str(path.relative_to(root)),
        "sha256_before": sha256(original),
        "sha256_after": sha256(patched),
        "required_marker": MARKER,
        "functions_path": FUNCTIONS_PATH,
        "kernel_function_name": KERNEL_FUNCTION_NAME,
        "diagnostic_tracing": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
