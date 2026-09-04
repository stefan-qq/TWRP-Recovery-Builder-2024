#!/usr/bin/env python3
import argparse
from pathlib import Path

FUNCTION_MARKER = 'MtpResponseCode MtpServer::doGetObject() {'
NEXT_FUNCTION_MARKER = 'MtpResponseCode MtpServer::doGetThumb() {'
IOCTL_CALL = 'ret = ioctl(mFD, MTP_SEND_FILE_WITH_HEADER, (unsigned long)&mfr);'
REPLACEMENT_CALL = (
    'ret = j720fSendFileInUserspace(mFD, mfr.fd, mfr.length, '
    'mfr.command, mfr.transaction_id);'
)
OLD_LOG = 'MTPD("MTP_SEND_FILE_WITH_HEADER returned %d\\n", ret);'
NEW_LOG = 'MTPD("J720F userspace send returned %d\\n", ret);'
HELPER_NAME = 'j720fSendFileInUserspace'

HELPER = r'''
static void j720fPutUInt16LE(unsigned char* out, uint16_t value) {
    out[0] = static_cast<unsigned char>(value & 0xff);
    out[1] = static_cast<unsigned char>((value >> 8) & 0xff);
}

static void j720fPutUInt32LE(unsigned char* out, uint32_t value) {
    out[0] = static_cast<unsigned char>(value & 0xff);
    out[1] = static_cast<unsigned char>((value >> 8) & 0xff);
    out[2] = static_cast<unsigned char>((value >> 16) & 0xff);
    out[3] = static_cast<unsigned char>((value >> 24) & 0xff);
}

static int j720fReadFileExact(int fileFd, unsigned char* buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count;
        do {
            count = read(fileFd, buffer + offset, length - offset);
        } while (count < 0 && errno == EINTR);

        if (count < 0)
            return -1;
        if (count == 0) {
            errno = EIO;
            return -1;
        }
        offset += static_cast<size_t>(count);
    }
    return 0;
}

static int j720fWriteMtpChunk(int mtpFd, const unsigned char* buffer, size_t length) {
    ssize_t count;
    do {
        count = write(mtpFd, buffer, length);
    } while (count < 0 && errno == EINTR);

    // The MTP gadget write path is expected to consume one complete transfer.
    // Retrying a positive short write would introduce a premature USB short
    // packet in the middle of the MTP data container, so fail it explicitly.
    if (count < 0)
        return -1;
    if (static_cast<size_t>(count) != length) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int j720fSendFileInUserspace(int mtpFd, int fileFd, int64_t fileLength,
        uint16_t command, uint32_t transactionId) {
    if (fileLength < 0) {
        errno = EINVAL;
        return -1;
    }

    if (lseek(fileFd, 0, SEEK_SET) < 0)
        return -1;

    // Keep full intermediate gadget writes at 16 KiB.  The first write combines
    // the 12-byte MTP data-container header with file bytes so a large transfer
    // does not end its first USB request with a premature short packet.
    unsigned char buffer[16384];
    const size_t headerSize = 12;
    uint64_t remaining = static_cast<uint64_t>(fileLength);
    const uint64_t totalLength = remaining + headerSize;
    const uint32_t containerLength = totalLength > 0xffffffffULL
            ? 0xffffffffU : static_cast<uint32_t>(totalLength);

    j720fPutUInt32LE(buffer + 0, containerLength);
    j720fPutUInt16LE(buffer + 4, 2);  // MTP_CONTAINER_TYPE_DATA
    j720fPutUInt16LE(buffer + 6, command);
    j720fPutUInt32LE(buffer + 8, transactionId);

    size_t firstPayload = sizeof(buffer) - headerSize;
    if (remaining < firstPayload)
        firstPayload = static_cast<size_t>(remaining);
    if (firstPayload > 0 && j720fReadFileExact(fileFd, buffer + headerSize, firstPayload) < 0)
        return -1;
    if (j720fWriteMtpChunk(mtpFd, buffer, headerSize + firstPayload) < 0)
        return -1;
    remaining -= firstPayload;

    while (remaining > 0) {
        size_t request = sizeof(buffer);
        if (remaining < request)
            request = static_cast<size_t>(remaining);
        if (j720fReadFileExact(fileFd, buffer, request) < 0)
            return -1;
        if (j720fWriteMtpChunk(mtpFd, buffer, request) < 0)
            return -1;
        remaining -= request;
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
    start = text.find(FUNCTION_MARKER)
    if start < 0:
        raise SystemExit('doGetObject(): function marker not found')
    if text.find(FUNCTION_MARKER, start + 1) >= 0:
        raise SystemExit('doGetObject(): expected one function marker')

    end = text.find(NEXT_FUNCTION_MARKER, start)
    if end < 0:
        raise SystemExit('doGetObject(): could not find following doGetThumb() marker')

    if HELPER_NAME in text:
        raise SystemExit('J720F userspace MTP send correction already appears to be applied')

    before = text[:start]
    function = text[start:end]
    after = text[end:]

    if function.count(IOCTL_CALL) != 1:
        raise SystemExit(
            'doGetObject(): expected exactly one MTP_SEND_FILE_WITH_HEADER ioctl, '
            f'found {function.count(IOCTL_CALL)}'
        )
    if function.count(OLD_LOG) != 1:
        raise SystemExit(
            'doGetObject(): expected exactly one MTP_SEND_FILE_WITH_HEADER result log, '
            f'found {function.count(OLD_LOG)}'
        )

    function = function.replace(IOCTL_CALL, REPLACEMENT_CALL, 1)
    function = function.replace(OLD_LOG, NEW_LOG, 1)
    text = before + HELPER + function + after

    patched_start = text.find(FUNCTION_MARKER)
    patched_end = text.find(NEXT_FUNCTION_MARKER, patched_start)
    patched_function = text[patched_start:patched_end]

    required = (
        'static int j720fSendFileInUserspace(',
        'j720fPutUInt32LE(buffer + 0, containerLength);',
        'j720fPutUInt16LE(buffer + 4, 2);',
        'write(mtpFd, buffer, length)',
        'read(fileFd, buffer + offset, length - offset)',
        REPLACEMENT_CALL,
        NEW_LOG,
    )
    for needle in required:
        if needle not in text:
            raise SystemExit(f'post-patch verification failed: {needle}')

    if IOCTL_CALL in patched_function:
        raise SystemExit('post-patch verification failed: send-file-with-header ioctl remains in doGetObject()')
    if patched_function.count(REPLACEMENT_CALL) != 1:
        raise SystemExit('post-patch verification failed: expected one userspace send call')
    if OLD_LOG in patched_function:
        raise SystemExit('post-patch verification failed: old send ioctl result log remains')

    path.write_text(text)
    print(f'Patched legacy TWRP MTP outbound transfer into userspace: {path}')


if __name__ == '__main__':
    main()
