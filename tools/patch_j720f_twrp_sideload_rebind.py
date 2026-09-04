#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

FUNCTION_HEADER = """int
apply_from_adb(const char* install_file, pid_t* child_pid) {"""
CHILD_EXEC = 'execl("/sbin/recovery", "recovery", "--adbd"'
FUSE_HOST = 'FUSE_SIDELOAD_HOST_PATHNAME'
FUSE_EXIT = 'FUSE_SIDELOAD_HOST_EXIT_PATHNAME'
READY = 'property_set("sys.usb.ffs.ready", "0");'
REQUEST = 'property_set("j720f.usb.rebind_req", "adb");'

ENTRY_LINES = (
    '// The normal recovery adbd stop clears ffs.ready, but the sideload',
    '// minadbd child is not an init service. Queue the existing J720F one-shot',
    '// ADB composition before minadbd publishes FunctionFS ready so the Samsung',
    '// android_usb/ConfigFS gate is replayed exactly once for sideload.',
    READY,
    REQUEST,
)

CLEANUP_LINES = (
    '// minadbd is forked directly rather than managed as init.svc.adbd, so its',
    '// exit does not run the init action that normally clears ffs.ready. Reset',
    '// that stale state and queue a fresh one-shot bind for the normal adbd.',
    READY,
    REQUEST,
)


def find_statement(text: str, statement: str, start: int, end: int, label: str) -> re.Match[str]:
    """Find one live statement line in a source range, ignoring indentation.

    The pinned TWRP file uses one-space indentation in this function, while the
    earlier patcher accidentally assumed four spaces. Restricting each search to
    a known live section also avoids the historical apply_from_adb snippet kept
    inside a block comment before the sideload child is launched.
    """
    pattern = re.compile(
        rf'^(?P<indent>[ \t]*){re.escape(statement)}[ \t]*$',
        re.MULTILINE,
    )
    matches = list(pattern.finditer(text, start, end))
    if len(matches) != 1:
        raise SystemExit(
            f'adb_install.cpp: expected exactly one live {label}, found {len(matches)}'
        )
    return matches[0]


def require_pinned_shape(text: str) -> tuple[int, int, int, int]:
    """Return stable bounds around the live TWRP 3.3 sideload implementation."""
    if text.count(FUNCTION_HEADER) != 1:
        raise SystemExit(
            'adb_install.cpp: pinned apply_from_adb signature must occur exactly once'
        )

    header = text.index(FUNCTION_HEADER)
    try:
        child_exec = text.index(CHILD_EXEC, header)
        fuse_host = text.index(FUSE_HOST, child_exec)
        fuse_exit = text.index(FUSE_EXIT, fuse_host)
        final_return = text.index('return result;', fuse_exit)
    except ValueError as exc:
        raise SystemExit(f'adb_install.cpp: pinned sideload anchor missing: {exc}')

    if not (header < child_exec < fuse_host < fuse_exit < final_return):
        raise SystemExit('adb_install.cpp: pinned sideload anchors are out of order')
    return header, child_exec, fuse_exit, final_return


def verify_patched(text: str) -> None:
    header, child_exec, fuse_exit, final_return = require_pinned_shape(text)

    if text.count(READY) != 2:
        raise SystemExit('post-patch verification failed: expected two explicit ffs.ready resets')
    if text.count(REQUEST) != 2:
        raise SystemExit('post-patch verification failed: expected two one-shot ADB rebind requests')

    entry_stop = find_statement(text, 'stop_adbd();', header, child_exec, 'sideload stop_adbd()')
    entry_enable = find_statement(
        text, 'set_usb_driver(true);', entry_stop.end(), child_exec,
        'sideload set_usb_driver(true)'
    )
    entry_ready = find_statement(
        text, READY, entry_stop.end(), entry_enable.start(),
        'sideload-entry ffs.ready reset'
    )
    entry_request = find_statement(
        text, REQUEST, entry_ready.end(), entry_enable.start(),
        'sideload-entry rebind request'
    )

    cleanup_disable = find_statement(
        text, 'set_usb_driver(false);', fuse_exit, final_return,
        'sideload cleanup set_usb_driver(false)'
    )
    cleanup_restart = find_statement(
        text, 'maybe_restart_adbd();', cleanup_disable.end(), final_return,
        'sideload cleanup maybe_restart_adbd()'
    )
    cleanup_ready = find_statement(
        text, READY, cleanup_disable.end(), cleanup_restart.start(),
        'sideload-cleanup ffs.ready reset'
    )
    cleanup_request = find_statement(
        text, REQUEST, cleanup_ready.end(), cleanup_restart.start(),
        'sideload-cleanup rebind request'
    )

    if not (
        header < entry_stop.start() < entry_ready.start() < entry_request.start()
        < entry_enable.start() < child_exec
    ):
        raise SystemExit('post-patch verification failed: sideload entry ordering is not safe')
    if not (
        fuse_exit < cleanup_disable.start() < cleanup_ready.start()
        < cleanup_request.start() < cleanup_restart.start() < final_return
    ):
        raise SystemExit('post-patch verification failed: sideload cleanup ordering is not safe')


def format_insert(indent: str, lines: tuple[str, ...]) -> str:
    return '\n' + '\n'.join(indent + line for line in lines)


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
    header, child_exec, fuse_exit, final_return = require_pinned_shape(text)

    if args.verify_only:
        verify_patched(text)
        print(f'Verified J720F sideload FunctionFS rebind integration: {path}')
        return

    if REQUEST in text or READY in text:
        raise SystemExit('J720F sideload FunctionFS rebind correction already appears to be applied')

    entry_stop = find_statement(text, 'stop_adbd();', header, child_exec, 'sideload stop_adbd()')
    entry_enable = find_statement(
        text, 'set_usb_driver(true);', entry_stop.end(), child_exec,
        'sideload set_usb_driver(true)'
    )
    if entry_stop.end() >= entry_enable.start():
        raise SystemExit('adb_install.cpp: sideload entry anchors are out of order')

    cleanup_disable = find_statement(
        text, 'set_usb_driver(false);', fuse_exit, final_return,
        'sideload cleanup set_usb_driver(false)'
    )
    cleanup_restart = find_statement(
        text, 'maybe_restart_adbd();', cleanup_disable.end(), final_return,
        'sideload cleanup maybe_restart_adbd()'
    )
    if cleanup_disable.end() >= cleanup_restart.start():
        raise SystemExit('adb_install.cpp: sideload cleanup anchors are out of order')

    # Insert from the later source position first so the earlier offset remains valid.
    patched = (
        text[:cleanup_disable.end()]
        + format_insert(cleanup_disable.group('indent'), CLEANUP_LINES)
        + text[cleanup_disable.end():]
    )
    patched = (
        patched[:entry_stop.end()]
        + format_insert(entry_stop.group('indent'), ENTRY_LINES)
        + patched[entry_stop.end():]
    )

    verify_patched(patched)
    path.write_text(patched)
    print(f'Integrated J720F one-shot FunctionFS rebind with TWRP ADB sideload: {path}')


if __name__ == '__main__':
    main()
