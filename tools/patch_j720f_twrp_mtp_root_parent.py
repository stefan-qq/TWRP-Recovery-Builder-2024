#!/usr/bin/env python3
import argparse
from pathlib import Path

FUNCTION_MARKER = 'MtpResponseCode MtpServer::doSendObjectInfo() {'
NEXT_FUNCTION_MARKER = 'MtpResponseCode MtpServer::doSendObject() {'
OLD_CONDITION = 'if (parent == MTP_PARENT_ROOT) {'
NEW_CONDITION = 'if (parent == MTP_PARENT_ROOT || parent == 0) {'


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--recovery', required=True, help='Path to bootable/recovery checkout')
    args = parser.parse_args()

    path = Path(args.recovery) / 'mtp/legacy/MtpServer.cpp'
    if not path.is_file():
        raise SystemExit(f'missing pinned TWRP source: {path}')

    text = path.read_text()
    start = text.find(FUNCTION_MARKER)
    if start < 0:
        raise SystemExit('doSendObjectInfo(): function marker not found')
    if text.find(FUNCTION_MARKER, start + 1) >= 0:
        raise SystemExit('doSendObjectInfo(): expected one function marker')

    end = text.find(NEXT_FUNCTION_MARKER, start)
    if end < 0:
        raise SystemExit('doSendObjectInfo(): could not find following doSendObject() marker')

    before = text[:start]
    function = text[start:end]
    after = text[end:]

    if NEW_CONDITION in function:
        raise SystemExit('J720F MTP root-parent compatibility correction already appears to be applied')
    if function.count(OLD_CONDITION) != 1:
        raise SystemExit(
            'doSendObjectInfo(): expected exactly one MTP_PARENT_ROOT condition, '
            f'found {function.count(OLD_CONDITION)}'
        )

    # Android MTP uses MTP_PARENT_ROOT (0xffffffff) for a storage-root upload.
    # Fedora libmtp 1.1.22 was observed sending parent 0 for mtp-sendfile to the
    # storage root. TWRP already maps the standards root sentinel to its internal
    # root handle 0; accept the observed compatibility form through the same path.
    function = function.replace(OLD_CONDITION, NEW_CONDITION, 1)
    text = before + function + after

    patched_start = text.find(FUNCTION_MARKER)
    patched_end = text.find(NEXT_FUNCTION_MARKER, patched_start)
    patched_function = text[patched_start:patched_end]

    required = (
        NEW_CONDITION,
        'path = storage->getPath();',
        'parent = 0;',
        'mDatabase->getObjectFilePath(parent',
        'MTP_RESPONSE_INVALID_PARENT_OBJECT',
    )
    for needle in required:
        if needle not in patched_function:
            raise SystemExit(f'post-patch verification failed in doSendObjectInfo(): {needle}')

    if OLD_CONDITION in patched_function:
        raise SystemExit('post-patch verification failed: old root-only condition remains')
    if patched_function.count(NEW_CONDITION) != 1:
        raise SystemExit('post-patch verification failed: expected one widened root-parent condition')

    path.write_text(text)
    print(f'Patched legacy TWRP MTP storage-root parent compatibility: {path}')


if __name__ == '__main__':
    main()
