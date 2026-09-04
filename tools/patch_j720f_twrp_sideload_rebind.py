#!/usr/bin/env python3
import argparse
from pathlib import Path

FUNCTION_HEADER = """int
apply_from_adb(const char* install_file, pid_t* child_pid) {"""
ENTRY_OLD = '''    stop_adbd();
    set_usb_driver(true);'''
ENTRY_NEW = '''    stop_adbd();
    // The normal recovery adbd stop clears ffs.ready, but the sideload
    // minadbd child is not an init service. Queue the existing J720F one-shot
    // ADB composition before minadbd publishes FunctionFS ready so the Samsung
    // android_usb/ConfigFS gate is replayed exactly once for sideload.
    property_set("sys.usb.ffs.ready", "0");
    property_set("j720f.usb.rebind_req", "adb");
    set_usb_driver(true);'''

CLEANUP_OLD = '''    set_usb_driver(false);
    maybe_restart_adbd();'''
CLEANUP_NEW = '''    set_usb_driver(false);
    // minadbd is forked directly rather than managed as init.svc.adbd, so its
    // exit does not run the init action that normally clears ffs.ready. Reset
    // that stale state and queue a fresh one-shot bind for the normal adbd.
    property_set("sys.usb.ffs.ready", "0");
    property_set("j720f.usb.rebind_req", "adb");
    maybe_restart_adbd();'''

CHILD_EXEC = 'execl("/sbin/recovery", "recovery", "--adbd"'
FUSE_HOST = 'FUSE_SIDELOAD_HOST_PATHNAME'
FUSE_EXIT = 'FUSE_SIDELOAD_HOST_EXIT_PATHNAME'


def require_pinned_shape(text: str) -> tuple[int, int]:
    """Validate stable anchors in the exact TWRP 3.3 source pinned by CI.

    Do not try to parse the whole C++ function. This source intentionally keeps
    an older apply_from_adb implementation inside a block comment, which made
    brace/definition scanning unnecessarily fragile. The two live statement
    pairs we patch are unique in the pinned file and are safer anchors.
    """
    if text.count(FUNCTION_HEADER) != 1:
        raise SystemExit(
            'adb_install.cpp: pinned apply_from_adb signature must occur exactly once'
        )

    header = text.index(FUNCTION_HEADER)
    try:
        child_exec = text.index(CHILD_EXEC, header)
        fuse_host = text.index(FUSE_HOST, child_exec)
        fuse_exit = text.index(FUSE_EXIT, fuse_host)
    except ValueError as exc:
        raise SystemExit(f'adb_install.cpp: pinned sideload anchor missing: {exc}')

    if not (header < child_exec < fuse_host < fuse_exit):
        raise SystemExit('adb_install.cpp: pinned sideload anchors are out of order')
    return header, child_exec


def verify_patched(text: str) -> None:
    header, child_exec = require_pinned_shape(text)

    ready = 'property_set("sys.usb.ffs.ready", "0");'
    request = 'property_set("j720f.usb.rebind_req", "adb");'
    if text.count(ready) != 2:
        raise SystemExit('post-patch verification failed: expected two explicit ffs.ready resets')
    if text.count(request) != 2:
        raise SystemExit('post-patch verification failed: expected two one-shot ADB rebind requests')

    try:
        entry_stop = text.index('    stop_adbd();', header)
        entry_ready = text.index(ready, entry_stop)
        entry_req = text.index(request, entry_ready)
        entry_enable = text.index('    set_usb_driver(true);', entry_req)

        cleanup_disable = text.index('    set_usb_driver(false);', child_exec)
        cleanup_ready = text.index(ready, cleanup_disable)
        cleanup_req = text.index(request, cleanup_ready)
        restart = text.index('    maybe_restart_adbd();', cleanup_req)
    except ValueError as exc:
        raise SystemExit(f'post-patch verification failed: expected statement missing: {exc}')

    if not (header < entry_stop < entry_ready < entry_req < entry_enable < child_exec):
        raise SystemExit('post-patch verification failed: sideload entry ordering is not safe')
    if not (child_exec < cleanup_disable < cleanup_ready < cleanup_req < restart):
        raise SystemExit('post-patch verification failed: sideload cleanup ordering is not safe')

    # The original consecutive statement pairs must be gone after insertion.
    if ENTRY_OLD in text:
        raise SystemExit('post-patch verification failed: unpatched sideload entry pair remains')
    if CLEANUP_OLD in text:
        raise SystemExit('post-patch verification failed: unpatched sideload cleanup pair remains')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--recovery', required=True, help='Path to bootable/recovery checkout')
    parser.add_argument(
        '--verify-only', action='store_true',
        help='Verify that the J720F sideload rebind correction is already present'
    )
    args = parser.parse_args()

    path = Path(args.recovery) / 'adb_install.cpp'
    if not path.is_file():
        raise SystemExit(f'missing pinned TWRP source: {path}')

    text = path.read_text()
    require_pinned_shape(text)

    if args.verify_only:
        verify_patched(text)
        print(f'Verified J720F sideload FunctionFS rebind integration: {path}')
        return

    if 'j720f.usb.rebind_req' in text:
        raise SystemExit('J720F sideload FunctionFS rebind correction already appears to be applied')

    entry_count = text.count(ENTRY_OLD)
    cleanup_count = text.count(CLEANUP_OLD)
    if entry_count != 1:
        raise SystemExit(
            'adb_install.cpp: expected exactly one live stop_adbd()/set_usb_driver(true) pair, '
            f'found {entry_count}'
        )
    if cleanup_count != 1:
        raise SystemExit(
            'adb_install.cpp: expected exactly one live '
            'set_usb_driver(false)/maybe_restart_adbd() pair, '
            f'found {cleanup_count}'
        )

    header = text.index(FUNCTION_HEADER)
    entry = text.index(ENTRY_OLD)
    child_exec = text.index(CHILD_EXEC, header)
    cleanup = text.index(CLEANUP_OLD)
    if not (header < entry < child_exec < cleanup):
        raise SystemExit('adb_install.cpp: live sideload patch anchors are out of order')

    patched = text.replace(ENTRY_OLD, ENTRY_NEW, 1)
    patched = patched.replace(CLEANUP_OLD, CLEANUP_NEW, 1)
    verify_patched(patched)

    path.write_text(patched)
    print(f'Integrated J720F one-shot FunctionFS rebind with TWRP ADB sideload: {path}')


if __name__ == '__main__':
    main()
