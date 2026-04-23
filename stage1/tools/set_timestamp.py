#!/usr/bin/env python3
"""
Rewrite IMAGE_FILE_HEADER.TimeDateStamp on a PE to a fixed realistic value,
then recompute the optional header checksum. Runs post-link, before
Authenticode signing.

Why: fresh (within-72h) timestamps on an unknown binary are a mild detection
signal; exact-zero or 1970 timestamps are a stronger one. A realistic
non-fresh date reads as normal for a signed OEM utility.

Value: 2025-10-15 14:00:00 UTC (six months before 2026-04-23 ship date,
round hour). Single-sourced here; not parameterized to keep builds
reproducible.
"""

import sys
import pefile

# 2025-10-15 14:00:00 UTC -> Unix epoch seconds.
FIXED_TS = 1760536800

def main(argv):
    if len(argv) != 2:
        print(f"usage: {argv[0]} <pe-file>", file=sys.stderr)
        return 2
    pe = pefile.PE(argv[1])
    old = pe.FILE_HEADER.TimeDateStamp
    pe.FILE_HEADER.TimeDateStamp = FIXED_TS
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(argv[1])
    print(f"TimeDateStamp: 0x{old:08x} -> 0x{FIXED_TS:08x} (2025-10-15 14:00:00 UTC)")
    print(f"Checksum recomputed: 0x{pe.OPTIONAL_HEADER.CheckSum:08x}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
