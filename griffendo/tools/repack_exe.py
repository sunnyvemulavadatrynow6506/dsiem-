"""Rebuild Griffendo.exe from the original executable plus the modified sources.

Why a repack instead of a fresh PyInstaller build: a PyInstaller Windows build
needs Windows (or Wine) and the exact original dependency set.  The original
Griffendo.exe is a PyInstaller 6.22.3 one-file build for CPython 3.12, and its
package format is documented and stable, so this script:

  * keeps the original bootloader (everything before the embedded package,
    including the icon/manifest resources) byte-for-byte;
  * copies every original package entry byte-for-byte (DLLs, .pyd files,
    base_library.zip, runtime hooks, ...);
  * replaces only the Griffendo modules listed in PYZ_REPLACE (adding the new
    ones), the 'launcher' entry script and the web assets, and adds
    catalog/anomaly_catalog.json;
  * writes a new package TOC and cookie in the same format.

Must run under CPython 3.12 (bytecode magic is checked) with
PyInstaller==6.22.3 installed (used only for its archive reader/TOC encoder).

    python3.12 tools/repack_exe.py ORIGINAL.exe OUTPUT.exe
"""
from __future__ import annotations

import hashlib
import importlib.util
import marshal
import struct
import sys
import zlib
from pathlib import Path

import PyInstaller
from PyInstaller.archive.readers import CArchiveReader
from PyInstaller.archive.writers import CArchiveWriter

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

# PYZ module name -> source file.  co_filename mirrors the original build ("logplatform\\app.py").
PYZ_REPLACE = {
    "agent.collector": SRC / "agent" / "collector.py",
    "agent.sources": SRC / "agent" / "sources.py",            # new in v3
    "agent.continuous": SRC / "agent" / "continuous.py",      # new in v3
    "logplatform.app": SRC / "logplatform" / "app.py",
    "logplatform.db": SRC / "logplatform" / "db.py",
    "logplatform.parser": SRC / "logplatform" / "parser.py",
    "logplatform.anomalies": SRC / "logplatform" / "anomalies.py",
    "logplatform.settings": SRC / "logplatform" / "settings.py",   # new in v3
    "logplatform.state": SRC / "logplatform" / "state.py",         # new in v3
    "logplatform.timeline": SRC / "logplatform" / "timeline.py",   # new in v3
    "logplatform.activity": SRC / "logplatform" / "activity.py",   # new in v4
    "logplatform.detection_api": SRC / "logplatform" / "detection_api.py",   # new in v5
    "logplatform.busy": SRC / "logplatform" / "busy.py",                     # new in v5.1
}
# v5: the detection engine and every rule module (one file per rule) - packages are marked as such.
PYZ_PACKAGES: set[str] = set()
for _path in sorted((SRC / "logplatform" / "detection").rglob("*.py")):
    _parts = list(_path.relative_to(SRC).with_suffix("").parts)
    if _parts[-1] == "__init__":
        _parts = _parts[:-1]
        PYZ_PACKAGES.add(".".join(_parts))
    PYZ_REPLACE[".".join(_parts)] = _path
SCRIPT_REPLACE = {"launcher": SRC / "launcher.py"}
DATA_REPLACE = {
    "web\\app.js": ROOT / "web" / "app.js",
    "web\\index.html": ROOT / "web" / "index.html",
    "web\\styles.css": ROOT / "web" / "styles.css",
}
DATA_ADD = {"catalog\\anomaly_catalog.json": ROOT / "catalog" / "anomaly_catalog.json",
            "web\\detections.js": ROOT / "web" / "detections.js"}

PYZ_ITEM_MODULE = 0
PYZ_ITEM_PKG = 1


def compile_source(path: Path, co_filename: str):
    return compile(path.read_text(encoding="utf-8"), co_filename, "exec", dont_inherit=True, optimize=0)


def build_pyz(original: bytes) -> tuple[bytes, list[str]]:
    assert original[:4] == b"PYZ\0", "not a PYZ archive"
    assert original[4:8] == importlib.util.MAGIC_NUMBER, "bytecode magic differs: run this with CPython 3.12"
    (toc_offset,) = struct.unpack("!i", original[8:12])
    toc = marshal.loads(original[toc_offset:])
    entries = dict(toc) if isinstance(toc, list) else toc
    out = bytearray(original[:17])          # header placeholder, same size as PyInstaller's
    new_toc = []
    changed = []
    names = list(entries)
    for name in PYZ_REPLACE:
        if name not in entries:
            names.append(name)
    names.sort()
    for name in names:
        if name in PYZ_REPLACE:
            is_package = name in PYZ_PACKAGES
            filename = name.replace(".", "\\") + ("\\__init__.py" if is_package else ".py")
            code = compile_source(PYZ_REPLACE[name], filename)
            blob = zlib.compress(marshal.dumps(code), 6)
            typecode = PYZ_ITEM_PKG if is_package else PYZ_ITEM_MODULE
            changed.append(name)
        else:
            typecode, offset, length = entries[name]
            blob = original[offset:offset + length]
        new_toc.append((name, (typecode, len(out), len(blob))))
        out += blob
    toc_at = len(out)
    out += marshal.dumps(new_toc)
    out[0:4] = b"PYZ\0"
    out[4:8] = importlib.util.MAGIC_NUMBER
    out[8:12] = struct.pack("!i", toc_at)
    return bytes(out), changed


def main(source: str, target: str) -> int:
    if PyInstaller.__version__ != "6.22.3":
        raise SystemExit(f"PyInstaller 6.22.3 required for an identical package format (found {PyInstaller.__version__})")
    exe = Path(source).read_bytes()
    reader = CArchiveReader(source)
    cookie = exe[reader._end_offset - CArchiveWriter._COOKIE_LENGTH:reader._end_offset]
    magic, archive_length, _, _, pyvers, pylib = struct.unpack(CArchiveWriter._COOKIE_FORMAT, cookie)
    package_start = reader._end_offset - archive_length
    if reader._end_offset != len(exe):
        raise SystemExit("unexpected trailing data after the package (signed executable?)")
    bootloader = exe[:package_start]

    def raw(name):
        offset, clen, dlen, compressed, typecode = reader.toc[name]
        return exe[reader._start_offset + offset: reader._start_offset + offset + clen], dlen, compressed, typecode

    package = bytearray()
    toc = []
    report = []

    def add(name, blob, data_length, compressed, typecode):
        toc.append((len(package), len(blob), data_length, compressed, typecode, name))
        package.extend(blob)

    for name in reader.toc:
        blob, dlen, compressed, typecode = raw(name)
        if name == "PYZ.pyz":
            pyz, changed = build_pyz(blob)
            add(name, pyz, len(pyz), 0, typecode)
            rules = [m for m in changed if ".detection.rules." in m and m.rsplit(".", 1)[-1].startswith("rule_")]
            others = [m for m in changed if m not in rules]
            report.append(f"PYZ.pyz rebuilt; {len(rules)} rule modules and {len(others)} other modules replaced/added: "
                          f"{', '.join(others)}")
        elif name in SCRIPT_REPLACE:
            code = compile_source(SCRIPT_REPLACE[name], f"{name}.py")
            data = marshal.dumps(code)
            add(name, zlib.compress(data, 9) if compressed else data, len(data), compressed, typecode)
            report.append(f"script {name} replaced")
        elif name in DATA_REPLACE:
            data = DATA_REPLACE[name].read_bytes()
            add(name, zlib.compress(data, 9) if compressed else data, len(data), compressed, typecode)
            report.append(f"data {name} replaced ({len(data)} bytes)")
        else:
            add(name, blob, dlen, compressed, typecode)
    for name, path in DATA_ADD.items():
        data = path.read_bytes()
        add(name, zlib.compress(data, 9), len(data), 1, "b")
        report.append(f"data {name} added ({len(data)} bytes)")

    toc_data = CArchiveWriter._serialize_toc(toc)
    toc_offset = len(package)
    archive_length = toc_offset + len(toc_data) + CArchiveWriter._COOKIE_LENGTH
    cookie = struct.pack(CArchiveWriter._COOKIE_FORMAT, magic, archive_length, toc_offset, len(toc_data), pyvers, pylib)
    output = bootloader + bytes(package) + toc_data + cookie
    Path(target).write_bytes(output)
    for line in report:
        print(line)
    print(f"bootloader preserved: {len(bootloader)} bytes (sha256 {hashlib.sha256(bootloader).hexdigest()[:16]}…)")
    print(f"wrote {target}: {len(output)} bytes, sha256 {hashlib.sha256(output).hexdigest()}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
