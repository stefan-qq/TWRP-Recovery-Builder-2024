#!/usr/bin/env python3
"""Disable Samsung DEFEX execve credential interception in the J720F recovery kernel only.

The SM-J720F CUL1 recovery image uses Samsung's stock Android-10-era kernel. Hardware
tracing proved that a root adbd command child reaches execve() as uid/euid/gid/egid 0,
but the ELF interpreter starts as uid/gid 2000. The stock kernel also contains Samsung
DEFEX and the classic Oreo-era DEFEX execve selector instruction patched by Magisk.

Patch only the kernel payload embedded in recovery.img, using the exact same 4-byte,
length-preserving transformation used by Magisk for Samsung DEFEX. The source prebuilt
kernel remains pristine; only the generated recovery artifact is modified. Fail closed
unless the exact known stock kernel hash and unique instruction offset match.
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
PATCHED_KERNEL_SHA256 = "03e4c4e2dbe3fe32051e71e295d1bb8901fca5565ff3b58f81272a1a498b4d18"
DEFEX_EXECVE_OLD = bytes.fromhex("821B8012")
DEFEX_EXECVE_NEW = bytes.fromhex("E2FF8F12")
EXPECTED_KERNEL_OFFSET = 0x154524


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

    status: str
    if kernel_sha256_before == PATCHED_KERNEL_SHA256:
        if kernel[EXPECTED_KERNEL_OFFSET : EXPECTED_KERNEL_OFFSET + 4] != DEFEX_EXECVE_NEW:
            raise RuntimeError("patched kernel hash matched but DEFEX replacement bytes did not")
        status = "already_patched"
    else:
        if kernel_sha256_before != STOCK_KERNEL_SHA256:
            raise RuntimeError(
                "refusing to patch unknown kernel: "
                f"sha256={kernel_sha256_before}, expected stock {STOCK_KERNEL_SHA256}"
            )

        offsets: list[int] = []
        pos = 0
        while True:
            hit = kernel.find(DEFEX_EXECVE_OLD, pos)
            if hit < 0:
                break
            offsets.append(hit)
            pos = hit + 1

        if offsets != [EXPECTED_KERNEL_OFFSET]:
            raise RuntimeError(
                "DEFEX execve selector did not occur exactly at the audited offset: "
                f"found {[hex(x) for x in offsets]}, expected {hex(EXPECTED_KERNEL_OFFSET)}"
            )

        absolute = kernel_start + EXPECTED_KERNEL_OFFSET
        blob[absolute : absolute + 4] = DEFEX_EXECVE_NEW
        patched_kernel = bytes(blob[kernel_start:kernel_end])
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
        "kernel_offset": EXPECTED_KERNEL_OFFSET,
        "kernel_offset_hex": hex(EXPECTED_KERNEL_OFFSET),
        "image_offset": kernel_start + EXPECTED_KERNEL_OFFSET,
        "image_offset_hex": hex(kernel_start + EXPECTED_KERNEL_OFFSET),
        "before_hex": DEFEX_EXECVE_OLD.hex(),
        "after_hex": DEFEX_EXECVE_NEW.hex(),
        "scope": "recovery image only; source prebuilt kernel remains unchanged",
    }

    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
