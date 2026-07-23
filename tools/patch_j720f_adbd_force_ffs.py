#!/usr/bin/env python3
"""Force recovery adbd into FunctionFS and instrument its one-shot main gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

MAIN_GATE = "J720F_MAIN_USB_GATE"
MAIN_DECISION = "J720F_MAIN_USB_DECISION"
TRANSPORT = "native-android71-ffs"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def patch_main(text: str) -> str:
    if MAIN_GATE in text or MAIN_DECISION in text:
        raise RuntimeError("daemon/main.cpp is already force-FFS patched")
    for anchor in (
        "bool is_usb = false;",
        "USB_FFS_ADB_EP0",
        "usb_init();",
        "DEFAULT_ADB_LOCAL_TRANSPORT_PORT",
    ):
        if anchor not in text:
            raise RuntimeError(f"daemon/main.cpp missing anchor: {anchor}")

    pattern = re.compile(
        r"(?ms)"
        r"^[ \t]*bool[ \t]+is_usb[ \t]*=[ \t]*false;[ \t]*\n"
        r"[ \t]*\n"
        r"^[ \t]*#if[ \t]+defined\(__ANDROID__\)[ \t]*\n"
        r"^[ \t]*if[ \t]*\("
        r"(?:access\(USB_ADB_PATH,[ \t]*F_OK\)[ \t]*==[ \t]*0[ \t]*\|\|[ \t]*)?"
        r"access\(USB_FFS_ADB_EP0,[ \t]*F_OK\)[ \t]*==[ \t]*0"
        r"\)[ \t]*\{[ \t]*\n"
        r"^[ \t]*//[ \t]*Listen[ \t]+on[ \t]+USB\.[ \t]*\n"
        r"^[ \t]*usb_init\(\);[ \t]*\n"
        r"^[ \t]*is_usb[ \t]*=[ \t]*true;[ \t]*\n"
        r"^[ \t]*\}[ \t]*\n"
        r"^[ \t]*#endif"
    )

    replacement = '''    bool is_usb = false;

#if defined(__ANDROID__)
    char j720f_transport[PROPERTY_VALUE_MAX] = {};
    property_get("j720f.usb.transport", j720f_transport, "");
    const bool j720f_force_ffs =
            strcmp(j720f_transport, "native-android71-ffs") == 0;

    errno = 0;
    const int j720f_ep0_access = access(USB_FFS_ADB_EP0, F_OK);
    const int j720f_ep0_errno = errno;
    D("J720F_MAIN_USB_GATE path=%s access=%d errno=%d (%s) transport=%s",
      USB_FFS_ADB_EP0, j720f_ep0_access, j720f_ep0_errno,
      j720f_ep0_errno == 0 ? "ok" : strerror(j720f_ep0_errno),
      j720f_transport);

    // This recovery creates only ConfigFS FunctionFS ADB. The upstream
    // one-shot access() gate can race init or be denied without a visible AVC;
    // after that it permanently falls back to TCP 5555. Enter USB whenever
    // the recovery transport marker requests FunctionFS. The FunctionFS open
    // thread retries ep0 and emits the exact syscall/result trace.
    if (j720f_force_ffs || j720f_ep0_access == 0) {
        D("J720F_MAIN_USB_DECISION mode=functionfs force=%d access=%d errno=%d",
          j720f_force_ffs, j720f_ep0_access, j720f_ep0_errno);
        usb_init();
        is_usb = true;
    } else {
        D("J720F_MAIN_USB_DECISION mode=tcp-fallback force=%d access=%d errno=%d",
          j720f_force_ffs, j720f_ep0_access, j720f_ep0_errno);
    }
#endif'''

    updated, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise RuntimeError(f"daemon/main.cpp USB gate: expected one block, found {count}")
    return updated


def patch_usb(text: str) -> str:
    if "event=usb_init_transport" in text or "event=usb_init_choice" in text:
        raise RuntimeError("usb_linux_client.cpp is already force-FFS patched")
    for anchor in (
        "J720F_USB_DIAG",
        "void usb_init()",
        "const int ep0_access = access(USB_FFS_ADB_EP0, F_OK);",
        "if (access(USB_FFS_ADB_EP0, F_OK) == 0)",
        "usb_ffs_init();",
        "usb_adb_init();",
    ):
        if anchor not in text:
            raise RuntimeError(f"instrumented usb_linux_client.cpp missing anchor: {anchor}")

    old_entry = '''    errno = 0;
    const int ep0_access = access(USB_FFS_ADB_EP0, F_OK);
    const int ep0_errno = errno;
    j720f_usb_diag("event=usb_init ep0=%s access=%d errno=%d (%s)",
                    USB_FFS_ADB_EP0, ep0_access, ep0_errno,
                    ep0_errno == 0 ? "ok" : strerror(ep0_errno));'''
    new_entry = '''    char j720f_transport[PROPERTY_VALUE_MAX] = {};
    property_get("j720f.usb.transport", j720f_transport, "");
    const bool j720f_force_ffs =
            strcmp(j720f_transport, "native-android71-ffs") == 0;
    errno = 0;
    const int ep0_access = access(USB_FFS_ADB_EP0, F_OK);
    const int ep0_errno = errno;
    j720f_usb_diag("event=usb_init_transport transport=%s force_ffs=%d ep0=%s access=%d errno=%d (%s)",
                    j720f_transport, j720f_force_ffs, USB_FFS_ADB_EP0,
                    ep0_access, ep0_errno,
                    ep0_errno == 0 ? "ok" : strerror(ep0_errno));'''
    if text.count(old_entry) != 1:
        raise RuntimeError("usb_init diagnostic entry: exact anchor count is not one")
    text = text.replace(old_entry, new_entry, 1)

    old_choice = '''    if (access(USB_FFS_ADB_EP0, F_OK) == 0)
        usb_ffs_init();
    else
        usb_adb_init();'''
    new_choice = '''    if (j720f_force_ffs || ep0_access == 0) {
        j720f_usb_diag("event=usb_init_choice mode=functionfs force_ffs=%d access=%d errno=%d",
                        j720f_force_ffs, ep0_access, ep0_errno);
        usb_ffs_init();
    } else {
        j720f_usb_diag("event=usb_init_choice mode=legacy force_ffs=%d access=%d errno=%d",
                        j720f_force_ffs, ep0_access, ep0_errno);
        usb_adb_init();
    }'''
    if text.count(old_choice) != 1:
        raise RuntimeError("usb_init transport choice: exact anchor count is not one")
    return text.replace(old_choice, new_choice, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system-core", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    root = args.system_core.resolve()
    main_path = root / "adb/daemon/main.cpp"
    usb_path = root / "adb/usb_linux_client.cpp"
    for path in (main_path, usb_path):
        if not path.is_file():
            raise SystemExit(f"missing source file: {path}")

    original_main = main_path.read_text()
    original_usb = usb_path.read_text()
    patched_main = patch_main(original_main)
    patched_usb = patch_usb(original_usb)

    main_path.write_text(patched_main)
    usb_path.write_text(patched_usb)

    report = {
        "transport_marker": TRANSPORT,
        "daemon_main_source": str(main_path.relative_to(root)),
        "daemon_main_sha256_before": sha256(original_main),
        "daemon_main_sha256_after": sha256(patched_main),
        "usb_source": str(usb_path.relative_to(root)),
        "usb_sha256_before_force_ffs": sha256(original_usb),
        "usb_sha256_after_force_ffs": sha256(patched_usb),
        "required_markers": [
            MAIN_GATE,
            MAIN_DECISION,
            "event=usb_init_transport",
            "event=usb_init_choice",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
