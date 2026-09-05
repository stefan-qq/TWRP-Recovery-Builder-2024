#!/usr/bin/env python3
"""Force the J720F recovery adbd into the proven native FunctionFS transport."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

MARKER = "J720F_FORCE_FFS_ENTRY"
TRANSPORT = "native-android71-ffs"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def patch_main(text: str) -> str:
    if MARKER in text:
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
        r"(?:[ \t]*\n)*"
        r"(?:^[ \t]*#if[ \t]+defined\(__ANDROID__\)[ \t]*\n)?"
        r"^[ \t]*if[ \t]*\("
        r"(?:access\(USB_ADB_PATH,[ \t]*F_OK\)[ \t]*==[ \t]*0[ \t]*\|\|[ \t]*)?"
        r"access\(USB_FFS_ADB_EP0,[ \t]*F_OK\)[ \t]*==[ \t]*0"
        r"\)[ \t]*\{[ \t]*\n"
        r"^[ \t]*//[ \t]*Listen[ \t]+on[ \t]+USB\.[ \t]*\n"
        r"^[ \t]*usb_init\(\);[ \t]*\n"
        r"^[ \t]*is_usb[ \t]*=[ \t]*true;[ \t]*\n"
        r"^[ \t]*\}[ \t]*\n"
        r"(?:^[ \t]*#endif[ \t]*(?:\n|$))?"
    )

    replacement = '''    bool is_usb = false;

#if defined(__ANDROID__)
    // J720F_FORCE_FFS_ENTRY: this recovery creates only ConfigFS FunctionFS ADB.
    // The donor one-shot access() gate can race init and permanently choose TCP;
    // the device property is the authoritative transport selection instead.
    char j720f_transport[PROPERTY_VALUE_MAX] = {};
    property_get("j720f.usb.transport", j720f_transport, "");
    const bool j720f_force_ffs =
            strcmp(j720f_transport, "native-android71-ffs") == 0;

    if (j720f_force_ffs || access(USB_FFS_ADB_EP0, F_OK) == 0) {
        usb_init();
        is_usb = true;
    }
#endif
'''

    updated, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise RuntimeError(f"daemon/main.cpp USB gate: expected one block, found {count}")
    return updated


def patch_usb(text: str) -> str:
    if MARKER in text:
        raise RuntimeError("usb_linux_client.cpp is already force-FFS patched")
    for anchor in (
        "void usb_init()",
        "if (access(USB_FFS_ADB_EP0, F_OK) == 0)",
        "usb_ffs_init();",
        "usb_adb_init();",
    ):
        if anchor not in text:
            raise RuntimeError(f"usb_linux_client.cpp missing anchor: {anchor}")

    old_choice = '''    if (access(USB_FFS_ADB_EP0, F_OK) == 0)
        usb_ffs_init();
    else
        usb_adb_init();'''
    new_choice = '''    // J720F_FORCE_FFS_ENTRY: mirror daemon/main.cpp and prefer the explicitly
    // selected recovery FunctionFS transport even if ep0 is not visible yet.
    char j720f_transport[PROPERTY_VALUE_MAX] = {};
    property_get("j720f.usb.transport", j720f_transport, "");
    const bool j720f_force_ffs =
            strcmp(j720f_transport, "native-android71-ffs") == 0;

    if (j720f_force_ffs || access(USB_FFS_ADB_EP0, F_OK) == 0)
        usb_ffs_init();
    else
        usb_adb_init();'''
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
        "required_marker": MARKER,
        "diagnostic_tracing": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
