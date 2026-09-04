#!/usr/bin/env python3
import argparse
from pathlib import Path

FUNCTION_NAME = 'apply_from_adb('
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


def find_function(text: str) -> tuple[int, int]:
    marker = text.find(FUNCTION_NAME)
    if marker < 0:
        raise SystemExit('apply_from_adb(): function marker not found')
    if text.find(FUNCTION_NAME, marker + 1) >= 0:
        raise SystemExit('apply_from_adb(): expected exactly one function definition marker')

    brace = text.find('{', marker)
    if brace < 0:
        raise SystemExit('apply_from_adb(): opening brace not found')

    depth = 0
    for pos in range(brace, len(text)):
        char = text[pos]
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return marker, pos + 1
    raise SystemExit('apply_from_adb(): closing brace not found')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--recovery', required=True, help='Path to bootable/recovery checkout')
    args = parser.parse_args()

    path = Path(args.recovery) / 'adb_install.cpp'
    if not path.is_file():
        raise SystemExit(f'missing pinned TWRP source: {path}')

    text = path.read_text()
    start, end = find_function(text)
    function = text[start:end]

    if 'j720f.usb.rebind_req' in function:
        raise SystemExit('J720F sideload FunctionFS rebind correction already appears to be applied')

    if function.count(ENTRY_OLD) != 1:
        raise SystemExit(
            'apply_from_adb(): expected exactly one stop_adbd()/set_usb_driver(true) sequence, '
            f'found {function.count(ENTRY_OLD)}'
        )
    if function.count(CLEANUP_OLD) != 1:
        raise SystemExit(
            'apply_from_adb(): expected exactly one cleanup set_usb_driver(false)/maybe_restart_adbd() sequence, '
            f'found {function.count(CLEANUP_OLD)}'
        )

    function = function.replace(ENTRY_OLD, ENTRY_NEW, 1)
    function = function.replace(CLEANUP_OLD, CLEANUP_NEW, 1)
    patched = text[:start] + function + text[end:]

    patched_start, patched_end = find_function(patched)
    body = patched[patched_start:patched_end]

    required = (
        'stop_adbd();',
        'set_usb_driver(true);',
        'execl("/sbin/recovery", "recovery", "--adbd"',
        'FUSE_SIDELOAD_HOST_PATHNAME',
        'set_usb_driver(false);',
        'maybe_restart_adbd();',
    )
    for needle in required:
        if needle not in body:
            raise SystemExit(f'post-patch verification failed in apply_from_adb(): {needle}')

    if body.count('property_set("sys.usb.ffs.ready", "0");') != 2:
        raise SystemExit('post-patch verification failed: expected two explicit ffs.ready resets')
    if body.count('property_set("j720f.usb.rebind_req", "adb");') != 2:
        raise SystemExit('post-patch verification failed: expected two one-shot ADB rebind requests')

    # Entry ordering: request must be pending before minadbd can publish ready=1.
    entry_stop = body.index('stop_adbd();')
    entry_ready = body.index('property_set("sys.usb.ffs.ready", "0");', entry_stop)
    entry_req = body.index('property_set("j720f.usb.rebind_req", "adb");', entry_ready)
    entry_enable = body.index('set_usb_driver(true);', entry_req)
    child_exec = body.index('execl("/sbin/recovery", "recovery", "--adbd"', entry_enable)
    if not (entry_stop < entry_ready < entry_req < entry_enable < child_exec):
        raise SystemExit('post-patch verification failed: sideload entry ordering is not safe')

    # Cleanup ordering: make ready false before queuing the normal-adbd bind.
    cleanup_disable = body.rindex('set_usb_driver(false);')
    cleanup_ready = body.index('property_set("sys.usb.ffs.ready", "0");', cleanup_disable)
    cleanup_req = body.index('property_set("j720f.usb.rebind_req", "adb");', cleanup_ready)
    restart = body.index('maybe_restart_adbd();', cleanup_req)
    if not (cleanup_disable < cleanup_ready < cleanup_req < restart):
        raise SystemExit('post-patch verification failed: sideload cleanup ordering is not safe')

    path.write_text(patched)
    print(f'Integrated J720F one-shot FunctionFS rebind with TWRP ADB sideload: {path}')


if __name__ == '__main__':
    main()
