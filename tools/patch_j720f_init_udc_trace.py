#!/usr/bin/env python3
"""Instrument Android 7.1 init's ConfigFS UDC write for SM-J720F.

This diagnostic does not change USB sequencing. It patches only init/util.cpp's
write_file() path and records the exact PID 1 open/write errno plus immediate
USB/ConfigFS state around writes to g1/UDC. Output is appended to the existing
/tmp/J720F_ADBD_USB_TRACE.txt file that the device tree already pre-creates,
labels for init/adbd/recovery access, and includes in the runtime report.

Strict anchors make the build fail if the donor system/core source changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

MARKER = "J720F_INIT_UDC"
UDC_PATH = "/sys/kernel/config/usb_gadget/g1/UDC"
TRACE_PATH = "/tmp/J720F_ADBD_USB_TRACE.txt"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def git_output(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


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


def patch_util(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("init/util.cpp is already instrumented")

    include_anchor = "#include <errno.h>\n"
    if include_anchor not in text:
        raise RuntimeError("init/util.cpp missing errno include anchor")
    text = replace_once(
        text,
        include_anchor,
        include_anchor + "#include <dirent.h>\n#include <unistd.h>\n",
        "diagnostic include insertion",
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

    new_write = r'''// J720F init-side ConfigFS diagnostic. This branch is not a release build.
// It observes only the g1/UDC write and appends to the already-labeled adbd
// trace file. No USB state is changed by these helpers.
static const char* const kJ720fUdcPath = "/sys/kernel/config/usb_gadget/g1/UDC";
static const char* const kJ720fUdcTracePath = "/tmp/J720F_ADBD_USB_TRACE.txt";

static void j720f_init_udc_trace(const char* format, ...) {
    const int saved_errno = errno;
    int fd = TEMP_FAILURE_RETRY(open(kJ720fUdcTracePath, O_WRONLY | O_APPEND | O_CLOEXEC));
    if (fd < 0) {
        errno = saved_errno;
        return;
    }

    char line[1024];
    int prefix = snprintf(line, sizeof(line),
                          "J720F_INIT_UDC pid=%d uid=%d gid=%d ",
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
    TEMP_FAILURE_RETRY(write(fd, line, total));
    close(fd);
    errno = saved_errno;
}

static void j720f_init_udc_trace_file(const char* phase, const char* label,
                                      const char* path) {
    const int saved_errno = errno;
    int fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        const int operation_errno = errno;
        j720f_init_udc_trace("phase=%s item=%s path=%s open_ret=-1 errno=%d (%s)",
                             phase, label, path, operation_errno,
                             strerror(operation_errno));
        errno = saved_errno;
        return;
    }

    char value[512];
    ssize_t count = TEMP_FAILURE_RETRY(read(fd, value, sizeof(value) - 1));
    const int operation_errno = count < 0 ? errno : 0;
    close(fd);
    if (count < 0) {
        j720f_init_udc_trace("phase=%s item=%s path=%s read_ret=%zd errno=%d (%s)",
                             phase, label, path, count, operation_errno,
                             strerror(operation_errno));
        errno = saved_errno;
        return;
    }

    value[count] = '\0';
    while (count > 0 && (value[count - 1] == '\n' || value[count - 1] == '\r')) {
        value[--count] = '\0';
    }
    j720f_init_udc_trace("phase=%s item=%s path=%s value=%s",
                         phase, label, path, count == 0 ? "<empty>" : value);
    errno = saved_errno;
}

static void j720f_init_udc_trace_link(const char* phase, const char* label,
                                      const char* path) {
    const int saved_errno = errno;
    char target[512];
    ssize_t count = readlink(path, target, sizeof(target) - 1);
    const int operation_errno = count < 0 ? errno : 0;
    if (count < 0) {
        j720f_init_udc_trace("phase=%s item=%s path=%s readlink_ret=-1 errno=%d (%s)",
                             phase, label, path, operation_errno,
                             strerror(operation_errno));
    } else {
        target[count] = '\0';
        j720f_init_udc_trace("phase=%s item=%s path=%s target=%s",
                             phase, label, path, target);
    }
    errno = saved_errno;
}

static void j720f_init_udc_trace_dir(const char* phase, const char* label,
                                     const char* path) {
    const int saved_errno = errno;
    DIR* dir = opendir(path);
    if (dir == nullptr) {
        const int operation_errno = errno;
        j720f_init_udc_trace("phase=%s item=%s path=%s opendir_ret=-1 errno=%d (%s)",
                             phase, label, path, operation_errno,
                             strerror(operation_errno));
        errno = saved_errno;
        return;
    }

    char entries[768];
    size_t used = 0;
    entries[0] = '\0';
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        int written = snprintf(entries + used, sizeof(entries) - used,
                               "%s%s", used == 0 ? "" : ",", entry->d_name);
        if (written < 0) break;
        if (static_cast<size_t>(written) >= sizeof(entries) - used) {
            used = sizeof(entries) - 1;
            entries[used] = '\0';
            break;
        }
        used += static_cast<size_t>(written);
    }
    closedir(dir);
    j720f_init_udc_trace("phase=%s item=%s path=%s entries=%s",
                         phase, label, path, used == 0 ? "<empty>" : entries);
    errno = saved_errno;
}

static void j720f_init_udc_trace_configfs_owners(const char* phase) {
    const int saved_errno = errno;
    const char* root = "/sys/kernel/config/usb_gadget";
    DIR* dir = opendir(root);
    if (dir == nullptr) {
        const int operation_errno = errno;
        j720f_init_udc_trace("phase=%s item=configfs_gadgets opendir_ret=-1 errno=%d (%s)",
                             phase, operation_errno, strerror(operation_errno));
        errno = saved_errno;
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char path[512];
        int count = snprintf(path, sizeof(path), "%s/%s/UDC", root, entry->d_name);
        if (count <= 0 || count >= static_cast<int>(sizeof(path))) continue;
        j720f_init_udc_trace_file(phase, entry->d_name, path);
    }
    closedir(dir);
    errno = saved_errno;
}

static void j720f_init_udc_snapshot(const char* phase, const char* requested) {
    const int saved_errno = errno;
    struct stat st;
    errno = 0;
    int stat_result = stat("/sys/class/udc/13600000.dwc3", &st);
    const int stat_errno = stat_result == 0 ? 0 : errno;
    j720f_init_udc_trace("phase=%s event=snapshot requested=%s udc_present=%d errno=%d (%s)",
                         phase, requested, stat_result == 0 ? 1 : 0, stat_errno,
                         stat_errno == 0 ? "ok" : strerror(stat_errno));

    j720f_init_udc_trace_file(phase, "selinux_context", "/proc/self/attr/current");
    j720f_init_udc_trace_file(phase, "udc_state", "/sys/class/udc/13600000.dwc3/state");
    j720f_init_udc_trace_file(phase, "g1_udc", kJ720fUdcPath);
    j720f_init_udc_trace_file(phase, "idVendor", "/sys/kernel/config/usb_gadget/g1/idVendor");
    j720f_init_udc_trace_file(phase, "idProduct", "/sys/kernel/config/usb_gadget/g1/idProduct");
    j720f_init_udc_trace_link(phase, "ffs_adb_link",
                              "/sys/kernel/config/usb_gadget/g1/configs/c.1/ffs.adb");
    j720f_init_udc_trace_dir(phase, "functions",
                             "/sys/kernel/config/usb_gadget/g1/functions");
    j720f_init_udc_trace_dir(phase, "config_c1",
                             "/sys/kernel/config/usb_gadget/g1/configs/c.1");
    j720f_init_udc_trace_file(phase, "android_usb_enable",
                              "/sys/class/android_usb/android0/enable");
    j720f_init_udc_trace_file(phase, "android_usb_aliases",
                              "/sys/class/android_usb/android0/f_ffs/aliases");
    j720f_init_udc_trace_file(phase, "android_usb_functions",
                              "/sys/class/android_usb/android0/functions");
    j720f_init_udc_trace_configfs_owners(phase);
    errno = saved_errno;
}

int write_file(const char* path, const char* content) {
    const bool trace_udc = !strcmp(path, kJ720fUdcPath);
    if (trace_udc) {
        j720f_init_udc_trace("event=write_file_enter path=%s requested=%s", path, content);
        j720f_init_udc_snapshot("before", content);
    }

    int fd = TEMP_FAILURE_RETRY(open(path, O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600));
    if (fd == -1) {
        const int operation_errno = errno;
        if (trace_udc) {
            j720f_init_udc_trace("event=udc_open_result fd=-1 errno=%d (%s)",
                                 operation_errno, strerror(operation_errno));
            j720f_init_udc_snapshot("after_open_failure", content);
        }
        NOTICE("write_file: Unable to open '%s': %s\n", path, strerror(operation_errno));
        errno = operation_errno;
        return -1;
    }

    int result = android::base::WriteStringToFd(content, fd) ? 0 : -1;
    const int write_errno = result == -1 ? errno : 0;
    if (trace_udc) {
        j720f_init_udc_trace("event=udc_write_result fd=%d result=%d bytes=%zu errno=%d (%s)",
                             fd, result, strlen(content), write_errno,
                             write_errno == 0 ? "ok" : strerror(write_errno));
    }
    if (result == -1) {
        NOTICE("write_file: Unable to write to '%s': %s\n", path, strerror(write_errno));
    }

    close(fd);
    const int final_errno = errno;
    if (trace_udc) {
        j720f_init_udc_snapshot("after", content);
        j720f_init_udc_trace("event=write_file_exit path=%s requested=%s result=%d write_errno=%d (%s)",
                             path, content, result, write_errno,
                             write_errno == 0 ? "ok" : strerror(write_errno));
    }
    errno = final_errno;
    return result;
}
'''

    return replace_once(text, old_write, new_write, "write_file instrumentation")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system-core", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    root = args.system_core.resolve()
    source = root / "init/util.cpp"
    if not source.is_file():
        raise SystemExit(f"missing source: {source}")

    original = source.read_text()
    updated = patch_util(original)
    source.write_text(updated)

    report = {
        "repository": git_remote_url(root),
        "commit": git_output(root, "rev-parse", "HEAD"),
        "path": str(source.relative_to(root)),
        "before_sha256": sha256(original),
        "after_sha256": sha256(updated),
        "marker": MARKER,
        "udc_path": UDC_PATH,
        "trace_path": TRACE_PATH,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
