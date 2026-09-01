#!/usr/bin/env python3
"""Neutralize the proven Samsung J720F recovery-ADB exec credential downgrade.

Hardware tracing on SM-J720F/CUL1 proves that the Android 7.1 ADB command child
reaches execve() as uid/euid/gid/egid 0 in u:r:adbd:s0, while the ELF interpreter
starts as 2000/2000/2000/2000. Binary tracing of the exact stock recovery kernel
identified the /sbin/adbd-related credential replacement block at +0x154d18:

    5280fa02  mov w2, #0x7d0   // AID_SHELL = 2000

followed by stores into UID, GID, EUID and EGID before commit_creds(). Hardware
A/B testing proved that changing only that immediate to zero preserves UID/GID 0
through the linker and yields a working root adb shell.

Patch only the kernel payload embedded in recovery.img. Keep both disproven DEFEX
experiments stock: +0x154524 (generic execve selector) and +0x2f47d4 (different
"adb with root" credential path). The source prebuilt kernel remains pristine.
Fail closed on any unknown hash or unexpected instruction bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ANDROID_MAGIC = b"ANDROID!"
EXPECTED_PAGE_SIZE = 2048
EXPECTED_KERNEL_SIZE = 23_300_040
EXPECTED_IMAGE_NAME = b"SRPRA09A005RU"

STOCK_KERNEL_SHA256 = "f91660e294f4532d266d23f386f99f4e9c290859154236d82e5280af9f11d268"
PATCHED_KERNEL_SHA256 = "d33cf9471a60e8a3235a656bd949b18b1d0805945cc3072f463274bfe23f8a93"

# Disproven generic DEFEX selector experiment: must stay stock.
DEFEX_EXECVE_SELECTOR_OFFSET = 0x154524
DEFEX_EXECVE_SELECTOR_STOCK = bytes.fromhex("821B8012")
DEFEX_EXECVE_SELECTOR_OLD_EXPERIMENT = bytes.fromhex("E2FF8F12")

# Proven /sbin/adbd-related credential rewrite.
#   stock:   5280fa02  mov w2, #2000
#   patched: 52800002  mov w2, #0
ADB_EXEC_CRED_OFFSET = 0x154D18
ADB_EXEC_CRED_STOCK = bytes.fromhex("02FA8052")
ADB_EXEC_CRED_PATCHED = bytes.fromhex("02008052")

# Different DEFEX "adb with root" block tested on hardware and disproven for
# this exec path. It must remain stock.
OTHER_ADB_ROOT_OFFSET = 0x2F47D4
OTHER_ADB_ROOT_STOCK = bytes.fromhex("01FA8052")
OTHER_ADB_ROOT_OLD_EXPERIMENT = bytes.fromhex("01008052")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kernel_bounds(blob: bytes) -> tuple[int, int, int]:
    if len(blob) < EXPECTED_PAGE_SIZE or blob[:8] != ANDROID_MAGIC:
        raise RuntimeError("not the expected legacy Android recovery image")

    kernel_size = struct.unpack_from("<I", blob, 8)[0]
    page_size = struct.unpack_from("<I", blob, 36)[0]
    image_name = blob[48:64].split(b"\0", 1)[0]

    if page_size != EXPECTED_PAGE_SIZE:
        raise RuntimeError(f"unexpected boot page size {page_size}; expected {EXPECTED_PAGE_SIZE}")
    if kernel_size != EXPECTED_KERNEL_SIZE:
        raise RuntimeError(
            f"unexpected kernel size {kernel_size}; expected {EXPECTED_KERNEL_SIZE}"
        )
    if image_name != EXPECTED_IMAGE_NAME:
        raise RuntimeError(
            f"unexpected image name {image_name!r}; expected {EXPECTED_IMAGE_NAME!r}"
        )

    start = page_size
    end = start + kernel_size
    if end > len(blob):
        raise RuntimeError("kernel payload extends beyond recovery image")
    return start, end, kernel_size


def require_stock_disproven_offsets(kernel: bytes) -> None:
    selector = kernel[DEFEX_EXECVE_SELECTOR_OFFSET : DEFEX_EXECVE_SELECTOR_OFFSET + 4]
    if selector != DEFEX_EXECVE_SELECTOR_STOCK:
        if selector == DEFEX_EXECVE_SELECTOR_OLD_EXPERIMENT:
            raise RuntimeError("obsolete generic DEFEX execve-selector experiment is present")
        raise RuntimeError(
            f"unexpected bytes at generic DEFEX selector: {selector.hex()}"
        )

    other = kernel[OTHER_ADB_ROOT_OFFSET : OTHER_ADB_ROOT_OFFSET + 4]
    if other != OTHER_ADB_ROOT_STOCK:
        if other == OTHER_ADB_ROOT_OLD_EXPERIMENT:
            raise RuntimeError("obsolete alternate DEFEX ADB-root experiment is present")
        raise RuntimeError(
            f"unexpected bytes at alternate DEFEX ADB-root block: {other.hex()}"
        )


def validate_target(kernel: bytes, *, patched: bool) -> None:
    require_stock_disproven_offsets(kernel)
    expected = ADB_EXEC_CRED_PATCHED if patched else ADB_EXEC_CRED_STOCK
    actual = kernel[ADB_EXEC_CRED_OFFSET : ADB_EXEC_CRED_OFFSET + 4]
    if actual != expected:
        raise RuntimeError(
            "unexpected /sbin/adbd exec credential instruction at audited offset: "
            f"{actual.hex()}, expected {expected.hex()}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    blob = bytearray(args.image.read_bytes())
    image_sha256_before = sha256(blob)
    kernel_start, kernel_end, kernel_size = kernel_bounds(blob)
    kernel = bytes(blob[kernel_start:kernel_end])
    kernel_sha256_before = sha256(kernel)

    if kernel_sha256_before == PATCHED_KERNEL_SHA256:
        validate_target(kernel, patched=True)
        status = "already_patched"
    else:
        if kernel_sha256_before != STOCK_KERNEL_SHA256:
            raise RuntimeError(
                "refusing to patch unknown kernel: "
                f"sha256={kernel_sha256_before}, expected stock {STOCK_KERNEL_SHA256}"
            )
        validate_target(kernel, patched=False)

        absolute = kernel_start + ADB_EXEC_CRED_OFFSET
        blob[absolute : absolute + 4] = ADB_EXEC_CRED_PATCHED
        patched_kernel = bytes(blob[kernel_start:kernel_end])
        validate_target(patched_kernel, patched=True)
        patched_sha256 = sha256(patched_kernel)
        if patched_sha256 != PATCHED_KERNEL_SHA256:
            raise RuntimeError(
                f"post-patch kernel sha256={patched_sha256}; expected {PATCHED_KERNEL_SHA256}"
            )
        args.image.write_bytes(blob)
        status = "patched"

    final_blob = args.image.read_bytes()
    final_kernel = final_blob[kernel_start:kernel_end]
    report = {
        "status": status,
        "image": str(args.image),
        "image_sha256_before": image_sha256_before,
        "image_sha256_after": sha256(final_blob),
        "kernel_size": kernel_size,
        "kernel_sha256_before": kernel_sha256_before,
        "kernel_sha256_after": sha256(final_kernel),
        "adb_exec_cred_offset": ADB_EXEC_CRED_OFFSET,
        "adb_exec_cred_offset_hex": hex(ADB_EXEC_CRED_OFFSET),
        "image_offset": kernel_start + ADB_EXEC_CRED_OFFSET,
        "image_offset_hex": hex(kernel_start + ADB_EXEC_CRED_OFFSET),
        "before_hex": ADB_EXEC_CRED_STOCK.hex(),
        "after_hex": ADB_EXEC_CRED_PATCHED.hex(),
        "generic_defex_selector_offset": DEFEX_EXECVE_SELECTOR_OFFSET,
        "generic_defex_selector_stock_hex": DEFEX_EXECVE_SELECTOR_STOCK.hex(),
        "alternate_adb_root_offset": OTHER_ADB_ROOT_OFFSET,
        "alternate_adb_root_stock_hex": OTHER_ADB_ROOT_STOCK.hex(),
        "scope": "recovery image only; proven /sbin/adbd exec credential downgrade neutralization",
    }

    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
