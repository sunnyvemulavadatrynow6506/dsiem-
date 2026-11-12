"""Check that a repacked Griffendo.exe contains exactly the current sources.

    python3.12 tools/verify_exe.py ORIGINAL.exe dist/Griffendo.exe

Compares each replaced module/launcher as a code object (marshal bytes can
differ between runs because of reference flags, so equality of the compiled
code is the meaningful test), every web asset and the catalog byte-for-byte,
and every other package entry byte-for-byte against the original exe.
"""
import marshal
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import repack_exe as r  # noqa: E402
from PyInstaller.archive.readers import CArchiveReader  # noqa: E402


def main(original: str, rebuilt: str) -> int:
    new, old = CArchiveReader(rebuilt), CArchiveReader(original)
    pyz = new.extract("PYZ.pyz")
    toc = dict(marshal.loads(pyz[struct.unpack("!i", pyz[8:12])[0]:]))
    checks = []
    for name, path in r.PYZ_REPLACE.items():
        if name not in toc:
            checks.append((f"module {name} (missing from the exe)", False))
            continue
        typecode, offset, length = toc[name]
        code = marshal.loads(zlib.decompress(pyz[offset:offset + length]))
        package = name in r.PYZ_PACKAGES
        filename = name.replace(".", "\\") + ("\\__init__.py" if package else ".py")
        ok = code == r.compile_source(path, filename) and typecode == (r.PYZ_ITEM_PKG if package else r.PYZ_ITEM_MODULE)
        checks.append((f"module {name}", ok))
    for name, path in r.SCRIPT_REPLACE.items():
        checks.append((f"script {name}", marshal.loads(new.extract(name)) == r.compile_source(path, f"{name}.py")))
    for name, path in {**r.DATA_REPLACE, **r.DATA_ADD}.items():
        checks.append((f"data {name}", new.extract(name) == path.read_bytes()))
    untouched = [n for n in old.toc if n != "PYZ.pyz" and n not in r.SCRIPT_REPLACE and n not in r.DATA_REPLACE]
    checks.append((f"{len(untouched)} untouched entries identical to original",
                   all(old.extract(n) == new.extract(n) for n in untouched)))
    old_pyz = old.extract("PYZ.pyz")
    old_toc = dict(marshal.loads(old_pyz[struct.unpack("!i", old_pyz[8:12])[0]:]))
    kept = [n for n in old_toc if n not in r.PYZ_REPLACE]
    checks.append((f"{len(kept)} untouched PYZ modules identical to original",
                   all(old_pyz[old_toc[n][1]:old_toc[n][1] + old_toc[n][2]] == pyz[toc[n][1]:toc[n][1] + toc[n][2]] for n in kept)))
    # The frozen importer needs every parent of a module to be a package entry in the PYZ
    # (it has no namespace packages); this is what hid the rules/windows folder in the first v5 build.
    orphans = sorted({".".join(n.split(".")[:i]) for n in toc for i in range(1, n.count(".") + 1)
                      if toc.get(".".join(n.split(".")[:i]), (None,))[0] != r.PYZ_ITEM_PKG
                      and n.startswith("logplatform.")})
    checks.append((f"every logplatform module's parent is a package{'' if not orphans else ': missing ' + ', '.join(orphans[:5])}",
                   not orphans))
    # Every source module of the application must be in the exe (a forgotten new module only fails at run time).
    sources = [".".join(path.relative_to(r.SRC).with_suffix("").parts)
               for package in ("logplatform", "agent") for path in (r.SRC / package).glob("*.py")
               if path.name != "__init__.py"]
    absent = [name for name in sources if name not in toc]
    checks.append((f"all {len(sources)} application modules are in the PYZ{'' if not absent else ': missing ' + ', '.join(absent)}",
                   not absent))
    from logplatform.detection.rules.index import MODULES
    missing = [m for m in MODULES if f"logplatform.detection.rules.{m}" not in toc]
    checks.append((f"all {len(MODULES)} indexed rule modules are in the PYZ", not missing))
    for label, ok in checks:
        print(("OK   " if ok else "FAIL ") + label)
    return 0 if all(ok for _, ok in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
