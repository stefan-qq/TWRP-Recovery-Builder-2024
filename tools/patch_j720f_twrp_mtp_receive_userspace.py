#!/usr/bin/env python3
import argparse
from pathlib import Path

FUNCTION_MARKER = 'MtpResponseCode MtpServer::doSendObject() {'
NEXT_FUNCTION_MARKER = 'MtpResponseCode MtpServer::doDeleteObject() {'
IOCTL_CALL = 'ioctl(mFD, MTP_RECEIVE_FILE, (unsigned long)&mfr)'
HELPER_NAME = 'j720fReceiveFileInUserspace'

HELPER = r'''static int j720fReceiveFileInUserspace(int mtpFd, int fileFd,
        uint64_t length, bool untilShortPacket)
{
    char buffer[16384];

    while (untilShortPacket || length > 0) {
        size_t request = sizeof(buffer);
        if (!untilShortPacket && length < request)
            request = static_cast<size_t>(length);

        ssize_t count;
        do {
            count = read(mtpFd, buffer, request);
        } while (count < 0 && errno == EINTR);

        if (count < 0)
            return -1;
        if (count == 0) {
            if (untilShortPacket)
                return 0;
            errno = EIO;
            return -1;
        }

        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written;
            do {
                written = write(fileFd, buffer + offset, count - offset);
            } while (written < 0 && errno == EINTR);

            if (written <= 0) {
                if (written == 0)
                    errno = EIO;
                return -1;
            }
            offset += written;
        }

        if (untilShortPacket) {
            if (static_cast<size_t>(count) < request)
                return 0;
        } else {
            length -= static_cast<uint64_t>(count);
        }
    }

    return 0;
}

'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--recovery', required=True, help='Path to bootable/recovery checkout')
    args = parser.parse_args()

    path = Path(args.recovery) / 'mtp/legacy/MtpServer.cpp'
    if not path.is_file():
        raise SystemExit(f'missing pinned TWRP source: {path}')

    text = path.read_text()

    # read(2)/write(2) are used directly by the J720F userspace receive helper.
    if '#include <unistd.h>' not in text:
        include_anchor = '#include <fcntl.h>\n'
        if include_anchor not in text:
            raise SystemExit('could not find fcntl include anchor for unistd.h')
        text = text.replace(include_anchor, include_anchor + '#include <unistd.h>\n', 1)

    if HELPER_NAME in text:
        raise SystemExit('J720F userspace MTP receive correction already appears to be applied')

    start = text.find(FUNCTION_MARKER)
    if start < 0:
        raise SystemExit('doSendObject(): function marker not found')
    if text.find(FUNCTION_MARKER, start + 1) >= 0:
        raise SystemExit('doSendObject(): expected one function marker')

    end = text.find(NEXT_FUNCTION_MARKER, start)
    if end < 0:
        raise SystemExit('doSendObject(): could not find following doDeleteObject() marker')

    before = text[:start]
    function = text[start:end]
    after = text[end:]

    if function.count(IOCTL_CALL) != 1:
        raise SystemExit(
            'doSendObject(): expected exactly one MTP_RECEIVE_FILE ioctl, '
            f'found {function.count(IOCTL_CALL)}'
        )

    # Keep the existing header read, file creation and permissions unchanged.
    # Only replace the Samsung-kernel bulk receive ioctl for the remaining payload.
    function = function.replace(
        IOCTL_CALL,
        f'{HELPER_NAME}(mFD, mfr.fd, mfr.length, '
        '(mSendObjectFileSize == 0xFFFFFFFF))',
        1,
    )

    # Make the existing diagnostic truthful without depending on its logging macro/style.
    if 'MTP_RECEIVE_FILE returned' in function:
        function = function.replace(
            'MTP_RECEIVE_FILE returned',
            'J720F userspace receive returned',
            1,
        )

    text = before + HELPER + function + after

    # Verify the full-object receive path is corrected but do not disturb partial-object
    # handling or outbound MTP ioctls in this first, auditable fix.
    patched_start = text.find(FUNCTION_MARKER)
    patched_end = text.find(NEXT_FUNCTION_MARKER, patched_start)
    patched_function = text[patched_start:patched_end]

    required = (
        HELPER_NAME,
        'read(mtpFd, buffer, request)',
        'write(fileFd, buffer + offset, count - offset)',
        '(mSendObjectFileSize == 0xFFFFFFFF)',
        '#include <unistd.h>',
    )
    for needle in required:
        if needle not in text:
            raise SystemExit(f'post-patch verification failed: {needle}')

    if IOCTL_CALL in patched_function:
        raise SystemExit('post-patch verification failed: doSendObject still uses MTP_RECEIVE_FILE')
    if text.count(HELPER_NAME) != 2:
        raise SystemExit('post-patch verification failed: expected helper definition plus one call')

    path.write_text(text)
    print(f'Patched legacy TWRP full-object MTP receive path: {path}')


if __name__ == '__main__':
    main()
