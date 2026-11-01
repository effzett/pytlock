"""Aufruf der Go-Referenzimplementierung `tle` (drand/tlock) per subprocess.

Entscheidung (siehe docs/DESIGN.md): bittensor-drand nutzt ein eigenes
AES-GCM-Format und ist archiviert; tle erzeugt echtes tlock/age-Chiffrat.

Datenfluss beim Verschlüsseln: Python liest die Quelle, hasht sie und schreibt
sie in stdin von tle; stdout (Chiffrat) wird ebenfalls gehasht und direkt in
den Container geschrieben. Es entstehen keine Klartext-Zwischendateien.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import BinaryIO, Callable, Iterable

CHUNK = 1024 * 1024
TLE_VERSION = "v1.2.0"


class TleError(Exception):
    pass


class TleNotFound(TleError):
    pass


class TooEarly(TleError):
    """tle meldet 'too early to decrypt'."""


class Cancelled(Exception):
    pass


def _exe_name() -> str:
    return "tle.exe" if sys.platform == "win32" else "tle"


def find_tle() -> list[str]:
    """Sucht das tle-Binary. Reihenfolge:
    1. Umgebungsvariable PYTLOCK_TLE
    2. Im PyInstaller-Bundle (bin/tle)
    3. vendor/tle/ im Projektverzeichnis (Entwicklung)
    4. PATH
    """
    env = os.environ.get("PYTLOCK_TLE")
    if env:
        return [env]
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "bin" / _exe_name())
    project_root = Path(__file__).resolve().parents[2]
    candidates.append(project_root / "vendor" / "tle" / _exe_name())
    for c in candidates:
        if c.is_file():
            return [str(c)]
    found = shutil.which("tle")
    if found:
        return [found]
    raise TleNotFound(
        "Das Programm 'tle' wurde nicht gefunden. Installation: "
        f"go install github.com/drand/tlock/cmd/tle@{TLE_VERSION} "
        "oder PYTLOCK_TLE auf den Pfad setzen."
    )


ProgressCb = Callable[[int], None]


class Tle:
    def __init__(self, command: list[str] | None = None, network: str = "https://api.drand.sh/",
                 chain_hash: str = ""):
        self.command = command or find_tle()
        self.network = network
        self.chain_hash = chain_hash

    def _base_args(self) -> list[str]:
        args = list(self.command) + ["-n", self.network]
        if self.chain_hash:
            args += ["-c", self.chain_hash]
        return args

    def encrypt_args(self, round_no: int, force: bool = False) -> list[str]:
        args = self._base_args() + ["-e", "-r", str(round_no)]
        if force:
            args.append("-f")
        return args

    def decrypt_args(self) -> list[str]:
        return self._base_args() + ["-d"]

    def run_stream(self, args: list[str], src: BinaryIO, dst: BinaryIO,
                   in_hooks: Iterable[Callable[[bytes], None]] = (),
                   out_hooks: Iterable[Callable[[bytes], None]] = (),
                   progress: ProgressCb | None = None,
                   cancel: threading.Event | None = None) -> None:
        """Pumpt src -> tle -> dst. Hooks bekommen jeden Block (z. B. Hashes)."""
        in_hooks = list(in_hooks)
        out_hooks = list(out_hooks)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, creationflags=creationflags)
        except OSError as exc:
            raise TleNotFound(f"tle konnte nicht gestartet werden: {exc}") from exc

        writer_error: list[BaseException] = []
        stderr_buf = bytearray()

        def writer() -> None:
            done = 0
            try:
                while True:
                    if cancel is not None and cancel.is_set():
                        raise Cancelled()
                    block = src.read(CHUNK)
                    if not block:
                        break
                    for h in in_hooks:
                        h(block)
                    proc.stdin.write(block)
                    done += len(block)
                    if progress:
                        progress(done)
            except BrokenPipeError:
                pass  # tle hat abgebrochen; Fehler kommt über stderr/returncode
            except BaseException as exc:  # noqa: BLE001
                writer_error.append(exc)
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        def err_reader() -> None:
            stderr_buf.extend(proc.stderr.read())

        tw = threading.Thread(target=writer, daemon=True)
        te = threading.Thread(target=err_reader, daemon=True)
        tw.start()
        te.start()
        try:
            while True:
                block = proc.stdout.read(CHUNK)
                if not block:
                    break
                for h in out_hooks:
                    h(block)
                dst.write(block)
                if cancel is not None and cancel.is_set():
                    raise Cancelled()
        except BaseException:
            proc.kill()
            raise
        finally:
            tw.join()
            proc.wait()
            te.join()

        if writer_error:
            if isinstance(writer_error[0], Cancelled):
                raise Cancelled()
            raise writer_error[0]
        if proc.returncode != 0:
            msg = stderr_buf.decode("utf-8", "replace").strip()
            if "too early" in msg.lower():
                raise TooEarly(msg)
            raise TleError(f"tle beendet mit Code {proc.returncode}: {msg}")

    def encrypt_bytes(self, data: bytes, round_no: int, force: bool = False) -> bytes:
        import io
        out = io.BytesIO()
        self.run_stream(self.encrypt_args(round_no, force), io.BytesIO(data), out)
        return out.getvalue()

    def decrypt_bytes(self, data: bytes) -> bytes:
        import io
        out = io.BytesIO()
        self.run_stream(self.decrypt_args(), io.BytesIO(data), out)
        return out.getvalue()
