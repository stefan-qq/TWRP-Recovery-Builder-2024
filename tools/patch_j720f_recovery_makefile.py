#!/usr/bin/env python3
"""Stop pinned TWRP 3.3 from installing its redundant permissive.sh helper."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} PATH/TO/bootable/recovery/Android.mk", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    text = path.read_text()

    # TWRP 3.3 lists permissive.sh as a recovery-binary dependency.  The J720F
    # recovery init is already forced permissive before rc actions, so packaging
    # this late helper is redundant and conflicts with the final ramdisk audit.
    pattern = re.compile(r"(?m)^[ \t]*permissive\.sh[ \t]*\\[ \t]*\n")
    patched, count = pattern.subn("", text, count=1)

    if count == 0:
        if not re.search(r"(?m)^[ \t]*permissive\.sh[ \t]*\\[ \t]*$", text):
            print(f"{path}: permissive.sh dependency already absent")
            return 0
        print(f"{path}: failed to remove permissive.sh dependency", file=sys.stderr)
        return 1

    path.write_text(patched)
    print(f"{path}: removed redundant permissive.sh recovery dependency")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
