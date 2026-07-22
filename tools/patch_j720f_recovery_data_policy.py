#!/usr/bin/env python3
"""Patch the donor Android 7.1 recovery-only policy for TWRP /data access."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def patch_recovery_te(path: Path) -> dict[str, object]:
    text = path.read_text()
    needles = [
        "neverallow recovery data_file_type:file { no_w_file_perms no_x_file_perms };",
        "neverallow recovery data_file_type:dir no_w_dir_perms;",
    ]
    counts = {needle: text.count(needle) for needle in needles}
    if any(count != 1 for count in counts.values()):
        raise SystemExit(f"unexpected recovery.te neverallow counts: {counts}")

    replacement = (
        "# J720F TWRP recovery must manage /data. The device policy grants only\n"
        "# the targeted system_data_file and media_rw_data_file permissions.\n"
        "# The stock recovery-only data neverallow assertions are intentionally\n"
        "# omitted from this recovery image; Android system policy is not changed."
    )
    text = text.replace("\n".join(needles), replacement)
    path.write_text(text)
    return {"path": str(path), "removed": needles}


def patch_domain_te(path: Path) -> dict[str, object]:
    lines = path.read_text().splitlines()
    end = next(
        (i for i, line in enumerate(lines) if line.strip() == "} system_data_file:file no_w_file_perms;"),
        None,
    )
    if end is None:
        raise SystemExit("system_data_file write neverallow not found in domain.te")

    start = end
    while start >= 0 and lines[start].strip() != "neverallow {":
        start -= 1
    if start < 0:
        raise SystemExit("start of system_data_file neverallow block not found")

    block = lines[start : end + 1]
    required = ("-system_server", "-system_app", "-init", "-installd")
    for marker in required:
        if not any(line.strip().startswith(marker) for line in block):
            raise SystemExit(f"unexpected system_data_file block; missing {marker}")
    if any(line.strip() == "-recovery" for line in block):
        raise SystemExit("domain.te already exempts recovery")

    insert_at = next(i for i in range(start, end + 1) if lines[i].strip() == "-init") + 1
    indent = lines[insert_at - 1][:-len(lines[insert_at - 1].lstrip())]
    lines.insert(insert_at, f"{indent}-recovery")
    path.write_text("\n".join(lines) + "\n")
    return {
        "path": str(path),
        "block_start_line": start + 1,
        "inserted": "-recovery",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sepolicy", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    recovery = args.sepolicy / "recovery.te"
    domain = args.sepolicy / "domain.te"
    if not recovery.is_file() or not domain.is_file():
        raise SystemExit("expected Android 7.1 system/sepolicy recovery.te and domain.te")

    report = {
        "recovery_te": patch_recovery_te(recovery),
        "domain_te": patch_domain_te(domain),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
