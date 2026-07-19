#!/usr/bin/env python3
"""Move TWRP 3.3 ORS runtime FIFOs from read-only /sbin to writable /tmp."""

from __future__ import annotations

import sys
from pathlib import Path

OLD = ('#define ORS_INPUT_FILE "/sbin/orsin"\n'
       '#define ORS_OUTPUT_FILE "/sbin/orsout"\n')
NEW = ('#define ORS_INPUT_FILE "/tmp/orsin"\n'
       '#define ORS_OUTPUT_FILE "/tmp/orsout"\n')


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} PATH/TO/orscmd.h", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    text = path.read_text()
    if NEW in text and OLD not in text:
        print(f"{path}: ORS FIFO patch already present")
        return 0
    if text.count(OLD) != 1:
        print(f"{path}: unexpected ORS FIFO definitions", file=sys.stderr)
        return 1
    path.write_text(text.replace(OLD, NEW, 1))
    print(f"{path}: moved ORS FIFOs to /tmp")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
