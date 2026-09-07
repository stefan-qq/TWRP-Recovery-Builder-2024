#!/usr/bin/env python3
"""Guard TWRP 3.3 adopted-storage parsing against modern Android Binary XML.

The pinned J720F recovery source parses /data/system/storage.xml with RapidXML.
Modern Android can store that file in a non-text binary XML representation
(ABX). Feeding non-text data to this old parser can keep recovery in its parser
error path and grow /tmp/recovery.log without bound.

This patch deliberately does *not* implement ABX parsing. It preserves legacy
text-XML behavior, skips only the optional storage.xml metadata parse when the
file is not text XML, and continues the existing adopted-storage block-device
probe. It also makes the document cleanup null-safe because the guarded path
never creates an xml_document.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

MARKER = (
    "J720F storage.xml guard: unsupported non-text storage.xml; "
    "skipping legacy adopted-storage metadata"
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def function_region(text: str) -> tuple[int, int, str]:
    start_marker = "bool TWPartitionManager::Decrypt_Adopted() {"
    end_marker = "\nvoid TWPartitionManager::Remove_Partition_By_Path"
    if text.count(start_marker) != 1:
        raise SystemExit(
            "partitionmanager.cpp: expected exactly one Decrypt_Adopted() definition"
        )
    start = text.index(start_marker)
    end = text.find(end_marker, start)
    if end < 0:
        raise SystemExit(
            "partitionmanager.cpp: could not find end of pinned Decrypt_Adopted()"
        )
    return start, end, text[start:end]


def verify_text(text: str) -> None:
    _, _, func = function_region(text)

    required = (
        'PageManager::LoadFileToBuffer("/data/system/storage.xml", NULL)',
        "doc->parse<0>(xmlFile);",
        "const char* xml_start = xmlFile;",
        "while (*xml_start == ' ' || *xml_start == '\\t' ||",
        "if (*xml_start != '<') {",
        MARKER,
        "if (doc) {",
        "doc->clear();",
        "delete doc;",
        "free(xmlFile);",
    )
    for marker in required:
        if marker not in func:
            raise SystemExit(
                f"partitionmanager.cpp: storage.xml guard verification missing {marker!r}"
            )

    if func.count(MARKER) != 1:
        raise SystemExit("partitionmanager.cpp: unexpected storage.xml guard marker count")
    if func.count("doc->parse<0>(xmlFile);") != 1:
        raise SystemExit("partitionmanager.cpp: unexpected RapidXML parse call count")
    if func.index(MARKER) > func.index("doc->parse<0>(xmlFile);"):
        raise SystemExit("partitionmanager.cpp: non-text guard does not precede RapidXML parse")

    unsafe_cleanup = re.compile(
        r"if \(xmlFile\) \{\s*doc->clear\(\);\s*delete doc;\s*free\(xmlFile\);\s*\}",
        re.MULTILINE,
    )
    if unsafe_cleanup.search(func):
        raise SystemExit("partitionmanager.cpp: old null-unsafe xml_document cleanup remains")

    # The non-text path must not abort the whole adopted-storage probe. We only
    # skip metadata parsing; removable/adopted block handling below still runs.
    guard_start = func.index("if (*xml_start != '<') {")
    guard_else = func.index("} else {", guard_start)
    guard_body = func[guard_start:guard_else]
    if "return false" in guard_body or "return true" in guard_body:
        raise SystemExit("partitionmanager.cpp: storage.xml guard must not return early")


def patch_text(text: str) -> str:
    _, _, func = function_region(text)
    if MARKER in func:
        raise SystemExit("partitionmanager.cpp: storage.xml guard already appears applied")

    if func.count("doc->parse<0>(xmlFile);") != 1:
        raise SystemExit("partitionmanager.cpp: pinned RapidXML parse anchor changed")

    # Match only the outer storage.xml success block in Decrypt_Adopted().
    parse_block = re.compile(
        r"(?ms)^(?P<indent>[ \t]*)if \(xmlFile != NULL\) \{\n"
        r"(?P<body>.*?doc->parse<0>\(xmlFile\);.*?^)(?P=indent)\} else \{\n"
        r"(?P<elsebody>[ \t]*LOGINFO\(\"No /data/system/storage\.xml for adopted storage\\n\"\);\n"
        r"[ \t]*return false;\n)"
        r"(?P=indent)\}"
    )
    matches = list(parse_block.finditer(func))
    if len(matches) != 1:
        raise SystemExit(
            "partitionmanager.cpp: expected exactly one pinned storage.xml parse block, "
            f"found {len(matches)}"
        )

    match = matches[0]
    indent = match.group("indent")
    body = match.group("body")
    elsebody = match.group("elsebody")

    # Move the existing text-XML parsing body under an inner else without
    # changing any of its logic.
    body_indented = "".join(
        ("\t" + line if line.strip() else line)
        for line in body.splitlines(keepends=True)
    )

    replacement = (
        f"{indent}if (xmlFile != NULL) {{\n"
        f"{indent}\tconst char* xml_start = xmlFile;\n"
        f"{indent}\twhile (*xml_start == ' ' || *xml_start == '\\t' ||\n"
        f"{indent}\t       *xml_start == '\\r' || *xml_start == '\\n') {{\n"
        f"{indent}\t\txml_start++;\n"
        f"{indent}\t}}\n"
        f"{indent}\tif (*xml_start != '<') {{\n"
        f"{indent}\t\tLOGINFO(\"{MARKER}\\n\");\n"
        f"{indent}\t}} else {{\n"
        f"{body_indented}"
        f"{indent}\t}}\n"
        f"{indent}}} else {{\n"
        f"{elsebody}"
        f"{indent}}}"
    )

    patched_func = func[: match.start()] + replacement + func[match.end() :]

    cleanup = re.compile(
        r"(?ms)^(?P<indent>[ \t]*)if \(xmlFile\) \{\n"
        r"(?P=indent)[ \t]+doc->clear\(\);\n"
        r"(?P=indent)[ \t]+delete doc;\n"
        r"(?P=indent)[ \t]+free\(xmlFile\);\n"
        r"(?P=indent)\}"
    )
    cleanup_matches = list(cleanup.finditer(patched_func))
    if len(cleanup_matches) != 1:
        raise SystemExit(
            "partitionmanager.cpp: expected exactly one pinned xml cleanup block, "
            f"found {len(cleanup_matches)}"
        )
    cm = cleanup_matches[0]
    ci = cm.group("indent")
    cleanup_replacement = (
        f"{ci}if (xmlFile) {{\n"
        f"{ci}\tif (doc) {{\n"
        f"{ci}\t\tdoc->clear();\n"
        f"{ci}\t\tdelete doc;\n"
        f"{ci}\t}}\n"
        f"{ci}\tfree(xmlFile);\n"
        f"{ci}}}"
    )
    patched_func = (
        patched_func[: cm.start()] + cleanup_replacement + patched_func[cm.end() :]
    )

    start, end, _ = function_region(text)
    result = text[:start] + patched_func + text[end:]
    verify_text(result)
    return result


def write_report(path: Path, source: Path, before: str, after: str) -> None:
    report = {
        "patch": "j720f-twrp-storage-xml-nontext-guard",
        "source": str(source),
        "source_sha256_before": hashlib.sha256(before.encode()).hexdigest(),
        "source_sha256_after": hashlib.sha256(after.encode()).hexdigest(),
        "marker": MARKER,
        "scope": "TWPartitionManager::Decrypt_Adopted only",
        "behavior": [
            "preserve legacy text storage.xml RapidXML parsing",
            "skip optional storage.xml metadata parsing for non-text/ABX input",
            "continue existing adopted-storage block-device probing",
            "make xml_document cleanup null-safe",
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recovery", required=True, help="Pinned bootable/recovery checkout")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--report", help="Optional JSON patch report")
    args = parser.parse_args()

    recovery = Path(args.recovery)
    source = recovery / "partitionmanager.cpp"
    if not source.is_file():
        raise SystemExit("missing pinned TWRP partitionmanager.cpp")

    before = source.read_text()
    if args.verify_only:
        verify_text(before)
        print("Verified J720F non-text/ABX storage.xml guard")
        return

    after = patch_text(before)
    source.write_text(after)
    if args.report:
        write_report(Path(args.report), source, before, after)
    print("Guarded legacy TWRP adopted-storage XML parsing against non-text/ABX storage.xml")


if __name__ == "__main__":
    main()
