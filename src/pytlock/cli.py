"""Kommandozeile: pytlock encrypt|decrypt|info."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__, core, strings as S
from .config import Settings
from .drand import DrandError
from .tle import TleError, TleNotFound
from .tsa import TsaError


def parse_when(text: str) -> datetime:
    """ISO-8601 (ohne Zone = lokale Zeit) oder Dauer wie 30m, 12h, 7d."""
    units = {"m": 60, "h": 3600, "d": 86400}
    if text[-1:] in units and text[:-1].isdigit():
        # Dauer ab jetzt: Ausgangspunkt ist die lokale Uhr, die Prüfung „liegt in
        # der Zukunft“ erfolgt aber gegen drand.
        return datetime.now(timezone.utc) + timedelta(seconds=int(text[:-1]) * units[text[-1]])
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt


def _local(dt: datetime) -> str:
    return dt.astimezone().strftime("%d.%m.%Y %H:%M:%S %Z")


def _progress(phase: str, done: int, total: int) -> None:
    if total:
        print(f"\r{phase}: {100 * done // max(total, 1):3d} %", end="", file=sys.stderr)


def cmd_encrypt(a, st: Settings) -> int:
    target = parse_when(a.at)
    src = Path(a.file)
    out = Path(a.output) if a.output else src.with_name(core.default_output_name(target))
    res = core.encrypt_file(src, out, target, drand=st.drand(), tle=st.tle(), tsas=st.tsas,
                            post=st.post, anchors=st.anchors, progress=_progress)
    print(file=sys.stderr)
    first = min(res.stamps, key=lambda s: s.info.gen_time)
    print(S.MSG_DONE_ENCRYPT.format(output=res.output, unlock=_local(res.unlock_time),
                                    round=res.round, submitted=_local(first.info.gen_time),
                                    tsa=first.tsa_name))
    print("\n" + S.MSG_SOURCE_WARNING)
    return 0


def cmd_info(a, st: Settings) -> int:
    info = core.inspect(Path(a.file))
    print(format_info(info))
    for e in info.stamp_errors:
        print("Warnung:", e)
    return 0


def format_info(info: core.ContainerInfo) -> str:
    stamps = "; ".join(
        S.STAMP_OK.format(covers=s.covers, time=_local(s.info.gen_time), tsa=s.tsa_name,
                          chain=S.CHAIN_OK if s.info.chain_verified else S.CHAIN_NOK)
        for s in info.stamps) or S.UNKNOWN
    ok = {True: S.YES, False: S.NO, None: S.UNKNOWN}[info.payload_hash_ok]
    sub = _local(info.submission_time) if info.submission_time else S.UNKNOWN
    return S.INFO_TEMPLATE.format(unlock=_local(info.unlock_time), round=info.round,
                                  submitted=sub, stamps=stamps, payload_ok=ok)


def cmd_decrypt(a, st: Settings) -> int:
    out_dir = Path(a.dir) if a.dir else Path(a.file).parent
    try:
        r = core.decrypt_file(Path(a.file), out_dir, drand=st.drand(), tle=st.tle(),
                              progress=_progress)
    except core.NotYet as e:
        print(S.MSG_NOT_YET.format(unlock=_local(e.unlock_time),
                                   remaining=S.fmt_duration(e.remaining_seconds)))
        return 2
    print(file=sys.stderr)
    print(S.MSG_DONE_DECRYPT.format(output=r.output, size=r.size))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pytlock", description=S.APP_TITLE)
    p.add_argument("--version", action="version", version=f"pytlock {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("encrypt", help="Datei zeitgesperrt verschlüsseln")
    e.add_argument("file")
    e.add_argument("--at", required=True,
                   help="Zielzeit: ISO-8601 (z. B. 2027-01-01T12:00) oder Dauer (30m, 12h, 7d)")
    e.add_argument("-o", "--output")
    d = sub.add_parser("decrypt", help="pytlock-Datei entschlüsseln")
    d.add_argument("file")
    d.add_argument("-d", "--dir", help="Zielordner (Standard: neben der Eingabe)")
    i = sub.add_parser("info", help="Metadaten und Zeitstempel anzeigen")
    i.add_argument("file")
    a = p.parse_args(argv)
    st = Settings.load()
    try:
        return {"encrypt": cmd_encrypt, "decrypt": cmd_decrypt, "info": cmd_info}[a.cmd](a, st)
    except TleNotFound as exc:
        print(S.MSG_NO_TLE.format(detail=exc), file=sys.stderr)
    except DrandError as exc:
        print(S.MSG_NO_NETWORK.format(detail=exc), file=sys.stderr)
    except TsaError as exc:
        print(S.MSG_TSA.format(detail=exc), file=sys.stderr)
    except (core.PytlockError, TleError, OSError, ValueError) as exc:
        print(S.MSG_ERROR.format(detail=exc), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
