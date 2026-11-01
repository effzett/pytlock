# PyInstaller-Spezifikation. Aufruf im Projektwurzelverzeichnis:
#   pyinstaller packaging/pytlock.spec --noconfirm
# Erwartet das tle-Binary unter vendor/tle/ (siehe README).
import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent
exe_name = "tle.exe" if sys.platform == "win32" else "tle"
tle_path = ROOT / "vendor" / "tle" / exe_name
if not tle_path.is_file():
    raise SystemExit(f"tle fehlt: {tle_path}")

datas = [(str(ROOT / "src" / "pytlock" / "data" / "tsa"), "pytlock/data/tsa"),
         (str(ROOT / "LICENSE"), "."),
         (str(ROOT / "packaging" / "THIRD_PARTY.txt"), ".")]
binaries = [(str(tle_path), "bin")]

excludes = ["PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.Qt3DCore",
            "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtMultimedia", "PySide6.QtCharts",
            "PySide6.QtDataVisualization", "PySide6.QtPdf", "tkinter"]

a = Analysis([str(ROOT / "packaging" / "launch_gui.py")], pathex=[str(ROOT / "src")],
             binaries=binaries, datas=datas, hiddenimports=[], excludes=excludes,
             noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="pytlock", console=False,
          target_arch="arm64" if sys.platform == "darwin" else None, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, name="pytlock", upx=False)

if sys.platform == "darwin":
    app = BUNDLE(coll, name="pytlock.app", bundle_identifier="de.zenmeister.pytlock",
                 info_plist={"NSHighResolutionCapable": True,
                             "CFBundleShortVersionString": "0.1.3"})
