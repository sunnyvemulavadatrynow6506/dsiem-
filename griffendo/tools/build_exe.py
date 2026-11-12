"""Build Griffendo.exe on Windows — one command, no other steps.

    python tools/build_exe.py

Produces ``dist\\Griffendo.exe``: a single file you double-click.  It

  * asks Windows for elevation (UAC) through the embedded manifest, because reading the
    Security event log requires Administrator — without it, Security/4624/4625/4688 and
    the account-audit events are not readable and half the rules can never fire;
  * starts the receiver/dashboard on the loopback address (127.0.0.1) at port 8000
    (falls back to a free port when 8000 is taken) and opens the dashboard;
  * collects Windows Event Logs continuously and sends them to the local receiver.

Why this script exists: a Windows executable can only be built on Windows (or Wine).
The repository therefore ships the build recipe instead of a binary, so the .exe is
reproducible and never stale relative to the sources.

Requirements (installed automatically by ``install`` below if missing):

    Python 3.12 for Windows, and PyInstaller

    python tools/build_exe.py install     # pip installs the build + runtime deps
    python tools/build_exe.py             # builds dist\\Griffendo.exe

Notes
-----
* Python 3.12 is used because the rule files are compiled to bytecode and the packaged
  runtime must match; 3.11 or 3.13 also work, but keep one interpreter per build.
* ``--onedir`` produces ``dist\\Griffendo\\Griffendo.exe`` (starts in ~1 s instead of
  ~4 s because nothing is extracted to a temp folder on every run).  Use it if you run
  Griffendo on every boot; the single-file build is the default because it is easier to
  copy around.
* The manifest requests ``highestAvailable`` rather than ``requireAdministrator`` so a
  standard user can still run the dashboard with reduced coverage instead of being
  blocked; Windows shows the UAC prompt for administrators.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
BUILD = ROOT / "build"
NAME = "Griffendo"

MANIFEST = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Griffendo.EndpointSecurity" version="6.0.0.0"
                    processorArchitecture="*"/>
  <description>Griffendo - Windows Event Intelligence</description>
  <!-- Reading the Windows Security event log requires elevation. highestAvailable lets an
       administrator get a UAC prompt while a standard user still gets a working dashboard. -->
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="highestAvailable" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/> <!-- Windows 10/11 -->
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/> <!-- Windows 8.1 -->
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">permonitorv2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"""

RUNTIME = ["fastapi", "uvicorn", "pydantic", "requests"]
BUILD_DEPS = ["pyinstaller"]


def run(command: list[str]) -> None:
    print(">", " ".join(command))
    subprocess.check_call(command)


def install() -> None:
    pip = [sys.executable, "-m", "pip", "install", "--upgrade"]
    run(pip + BUILD_DEPS + RUNTIME)


def check_platform() -> None:
    if not sys.platform.startswith("win"):
        raise SystemExit(
            "Griffendo.exe can only be built on Windows (PyInstaller cannot cross-compile).\n"
            f"This machine reports: {sys.platform}.\n"
            "Run this script on the Windows endpoint you want to monitor, or in a Windows VM."
        )
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        raise SystemExit("PyInstaller is missing. Run:  python tools/build_exe.py install")


def build(onefile: bool = True) -> Path:
    check_platform()
    # The manifest is passed to PyInstaller as a resource; it is written next to the build.
    manifest = BUILD / "griffendo.manifest"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(MANIFEST, encoding="utf-8")

    for folder in (BUILD / "pyi", DIST):
        if folder.exists():
            shutil.rmtree(folder, ignore_errors=True)

    command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", NAME,
        "--onefile" if onefile else "--onedir",
        "--console",                       # keep a console: it shows collection status
        "--manifest", str(manifest),
        "--add-data", f"{ROOT / 'web'}{os.pathsep}web",
        "--add-data", f"{ROOT / 'catalog'}{os.pathsep}catalog",
        "--hidden-import", "logplatform.detection.rules.index",
        "--hidden-import", "uvicorn.logging",
        "--hidden-import", "uvicorn.loops.auto",
        "--hidden-import", "uvicorn.loops.asyncio",
        "--hidden-import", "uvicorn.protocols.http.auto",
        "--hidden-import", "uvicorn.protocols.http.h11_impl",
        "--hidden-import", "uvicorn.protocols.websockets.auto",
        "--hidden-import", "uvicorn.lifespan.on",
        "--paths", str(ROOT / "src"),
        "--collect-submodules", "logplatform",
        "--collect-submodules", "agent",
        "--distpath", str(DIST),
        "--workpath", str(BUILD / "pyi"),
        "--specpath", str(BUILD),
        str(ROOT / "src" / "launcher.py"),
    ]
    run(command)
    target = DIST / f"{NAME}.exe" if onefile else DIST / NAME / f"{NAME}.exe"
    if not target.exists():
        raise SystemExit(f"Build finished but {target} is missing — see the PyInstaller output above.")
    print(f"\nBuilt: {target}  ({target.stat().st_size / 1048576:.1f} MB)")
    print("Double-click it. Windows shows a UAC prompt (Administrator is needed for the Security log),")
    print("the dashboard opens at http://127.0.0.1:8000/ and event collection starts immediately.")
    return target


def main() -> int:
    args = [a for a in sys.argv[1:]]
    if "install" in args:
        install()
        return 0
    build(onefile="--onedir" not in args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
