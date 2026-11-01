"""Verschlüsseln, Prüfen und Entschlüsseln von pytlock-Containern.

Containerformat v1 (Details: docs/FORMAT.md) — ein ZIP (unkomprimiert, ZIP64):

    pytlock.json     öffentliche Metadaten
    payload.age      tlock/age-Chiffrat der Datei (mit `tle -d` entschlüsselbar)
    secret.age       tlock/age-Chiffrat eines kleinen JSON mit Salt,
                     Originaldateiname, Größe und SHA-256 des Klartexts
    payload.tsr      RFC-3161-Antwort über SHA-256(payload.age)
    commitment.tsr   RFC-3161-Antwort über SHA-256(salt || Klartext)
    LIESMICH.txt     Anleitung zur Prüfung ohne pytlock

Warum Salt/Commitment statt SHA-256(Klartext) offen? Bei kurzen oder
erratbaren Inhalten (z. B. "ja"/"nein") könnte jeder mit Zugriff auf den
Container Kandidaten hashen und vergleichen und so das Zeitschloss umgehen.
Das Salt liegt deshalb ebenfalls zeitgesperrt in secret.age.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable

from . import __version__
from .drand import ChainInfo, DrandClient, QUICKNET
from .tle import TLE_VERSION, Cancelled, Tle, TooEarly
from . import tsa as tsamod

FORMAT_NAME = "pytlock"
FORMAT_VERSION = 1
META = "pytlock.json"
PAYLOAD = "payload.age"
SECRET = "secret.age"
PAYLOAD_TSR = "payload.tsr"
COMMIT_TSR = "commitment.tsr"
README = "LIESMICH.txt"

Progress = Callable[[str, int, int], None]  # (phase, done, total)


class PytlockError(Exception):
    pass


class FormatError(PytlockError):
    pass


class TargetInPast(PytlockError):
    pass


class IntegrityError(PytlockError):
    pass


class NotYet(PytlockError):
    def __init__(self, target_round: int, latest_round: int, unlock_time: datetime,
                 remaining_seconds: int):
        self.target_round = target_round
        self.latest_round = latest_round
        self.unlock_time = unlock_time
        self.remaining_seconds = remaining_seconds
        super().__init__(f"Noch {remaining_seconds} s bis Runde {target_round}")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def default_output_name(target: datetime) -> str:
    # bewusst neutral: der Originaldateiname liegt verschlüsselt im Container
    return f"pytlock-{target.astimezone(timezone.utc):%Y%m%d-%H%M}Z.pytlock"


def safe_filename(name: str) -> str:
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r'[\x00-\x1f<>:"|?*]', "_", name).strip(" .")
    return name or "entschluesselt.bin"


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for i in range(1, 10000):
        cand = path.with_name(f"{stem} ({i}){suffix}")
        if not cand.exists():
            return cand
    raise PytlockError(f"Kein freier Dateiname für {path}")


class _ProgressReader:
    def __init__(self, fh: BinaryIO, cb: Callable[[int], None] | None):
        self.fh = fh
        self.cb = cb
        self.done = 0

    def read(self, n: int = -1) -> bytes:
        b = self.fh.read(n)
        self.done += len(b)
        if self.cb and b:
            self.cb(self.done)
        return b


# --------------------------------------------------------------------------
# Ergebnisse
# --------------------------------------------------------------------------

@dataclass
class StampResult:
    covers: str
    file: str
    tsa_name: str
    tsa_url: str
    info: tsamod.TimestampInfo


@dataclass
class EncryptResult:
    output: Path
    round: int
    unlock_time: datetime
    stamps: list[StampResult]


@dataclass
class ContainerInfo:
    path: Path
    meta: dict
    round: int
    unlock_time: datetime
    target_time: datetime
    stamps: list[StampResult]
    stamp_errors: list[str] = field(default_factory=list)
    payload_hash_ok: bool | None = None

    @property
    def submission_time(self) -> datetime | None:
        times = [s.info.gen_time for s in self.stamps]
        return min(times) if times else None


@dataclass
class DecryptResult:
    output: Path
    original_name: str
    size: int
    info: ContainerInfo


# --------------------------------------------------------------------------
# Verschlüsseln
# --------------------------------------------------------------------------

def encrypt_file(src: Path, dst: Path, target: datetime, *,
                 drand: DrandClient, tle: Tle,
                 tsas: list[dict] | None = None,
                 post: tsamod.PostFn = tsamod.http_post,
                 anchors=None,
                 progress: Progress | None = None,
                 cancel: threading.Event | None = None,
                 allow_past: bool = False) -> EncryptResult:
    src = Path(src)
    dst = Path(dst)
    if target.tzinfo is None:
        raise ValueError("Zielzeitpunkt muss zeitzonenbehaftet sein")
    chain: ChainInfo = drand.verify_chain()
    round_no = chain.round_at(target)
    latest = drand.latest_round()
    if round_no <= latest and not allow_past:
        raise TargetInPast(
            f"Der Zielzeitpunkt liegt laut drand in der Vergangenheit "
            f"(Runde {round_no} ≤ aktuelle Runde {latest}).")
    unlock_time = chain.round_time(round_no)
    tle.network = drand.active_relay or tle.network
    tle.chain_hash = chain.chain_hash

    total = src.stat().st_size
    salt = secrets.token_bytes(32)
    h_plain = hashlib.sha256()
    h_commit = hashlib.sha256(salt)
    h_payload = hashlib.sha256()
    payload_size = 0

    def count(b: bytes) -> None:
        nonlocal payload_size
        payload_size += len(b)

    part = dst.with_name(dst.name + ".part")
    try:
        with zipfile.ZipFile(part, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
            with open(src, "rb") as fin, zf.open(PAYLOAD, "w", force_zip64=True) as zout:
                tle.run_stream(
                    tle.encrypt_args(round_no, force=allow_past), fin, zout,
                    in_hooks=[h_plain.update, h_commit.update],
                    out_hooks=[h_payload.update, count],
                    progress=(lambda d: progress("encrypt", d, total)) if progress else None,
                    cancel=cancel,
                )
            secret = {
                "version": 1,
                "salt": salt.hex(),
                "filename": src.name,
                "size": total,
                "sha256": h_plain.hexdigest(),
            }
            secret_ct = tle.encrypt_bytes(json.dumps(secret).encode("utf-8"), round_no,
                                          force=allow_past)
            zf.writestr(SECRET, secret_ct)

            if cancel is not None and cancel.is_set():
                raise Cancelled()
            if progress:
                progress("timestamp", 0, 2)
            stamps: list[StampResult] = []
            for i, (covers, fname, digest) in enumerate((
                    ("payload", PAYLOAD_TSR, h_payload.digest()),
                    ("commitment", COMMIT_TSR, h_commit.digest()))):
                der, entry, info = tsamod.request_timestamp(digest, tsas, post=post,
                                                            anchors=anchors)
                zf.writestr(fname, der)
                stamps.append(StampResult(covers, fname, entry["name"], entry["url"], info))
                if progress:
                    progress("timestamp", i + 1, 2)

            meta = {
                "format": FORMAT_NAME,
                "version": FORMAT_VERSION,
                "created_by": f"pytlock {__version__}",
                "tle_version": TLE_VERSION,
                "target_time_utc": _iso(target),
                "drand": {
                    "beacon_id": chain.beacon_id,
                    "chain_hash": chain.chain_hash,
                    "scheme": chain.scheme,
                    "genesis_time": chain.genesis_time,
                    "period": chain.period,
                    "round": round_no,
                    "round_time_utc": _iso(unlock_time),
                    "relay": tle.network,
                },
                "payload": {"file": PAYLOAD, "size": payload_size,
                            "sha256": h_payload.hexdigest()},
                "secret": {"file": SECRET},
                "commitment": {"algorithm": "sha256(salt || plaintext)",
                               "sha256": h_commit.hexdigest()},
                "timestamps": [{
                    "covers": s.covers, "file": s.file, "tsa_name": s.tsa_name,
                    "tsa_url": s.tsa_url, "gen_time_utc": _iso(s.info.gen_time),
                    "serial": str(s.info.serial), "tsa_subject": s.info.tsa_subject,
                } for s in stamps],
            }
            zf.writestr(META, json.dumps(meta, indent=2, ensure_ascii=False))
            zf.writestr(README, _readme_text(meta))
        os.replace(part, dst)
    except BaseException:
        try:
            part.unlink()
        except FileNotFoundError:
            pass
        raise
    return EncryptResult(dst, round_no, unlock_time, stamps)


def _readme_text(meta: dict) -> str:
    d = meta["drand"]
    return f"""pytlock-Container (Format {meta['version']})

Entschlüsselbar ab: {d['round_time_utc']} (drand {d['beacon_id']}, Runde {d['round']})

Prüfung ohne pytlock (nach dem Entpacken dieses ZIP):

1. Datei entschlüsseln (ab der Zielrunde):
     tle -d -o datei payload.age

2. Zeitstempel über das Chiffrat prüfen:
     openssl ts -verify -in payload.tsr -data payload.age -CAfile <TSA-Wurzelzertifikat>

3. Zeitstempel über den Klartext prüfen (Salt aus secret.age):
     tle -d secret.age            # zeigt JSON mit "salt" (hex)
     (printf '%s' <salt-hex> | xxd -r -p; cat datei) > commit.bin
     openssl ts -verify -in commitment.tsr -data commit.bin -CAfile <TSA-Wurzelzertifikat>

Einlieferungszeit = genTime des Zeitstempels:
     openssl ts -reply -in payload.tsr -text
"""


# --------------------------------------------------------------------------
# Prüfen
# --------------------------------------------------------------------------

def _open(path: Path) -> zipfile.ZipFile:
    try:
        zf = zipfile.ZipFile(path, "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise FormatError(f"Keine pytlock-Datei: {exc}") from exc
    names = set(zf.namelist())
    missing = {META, PAYLOAD, SECRET} - names
    if missing:
        zf.close()
        raise FormatError(f"Container unvollständig, es fehlt: {', '.join(sorted(missing))}")
    return zf


def read_meta(zf: zipfile.ZipFile) -> dict:
    try:
        meta = json.loads(zf.read(META).decode("utf-8"))
    except ValueError as exc:
        raise FormatError(f"Metadaten unlesbar: {exc}") from exc
    if meta.get("format") != FORMAT_NAME:
        raise FormatError("Keine pytlock-Metadaten")
    if meta.get("version") != FORMAT_VERSION:
        raise FormatError(f"Formatversion {meta.get('version')} wird nicht unterstützt")
    if meta["drand"]["chain_hash"] != QUICKNET.chain_hash:
        raise FormatError("Unbekanntes drand-Netzwerk (Chain-Hash weicht ab)")
    return meta


def inspect(path: Path, *, anchors=None, check_payload_hash: bool = True,
            progress: Progress | None = None) -> ContainerInfo:
    path = Path(path)
    with _open(path) as zf:
        meta = read_meta(zf)
        round_no = int(meta["drand"]["round"])
        payload_ok = None
        if check_payload_hash:
            h = hashlib.sha256()
            total = zf.getinfo(PAYLOAD).file_size
            with zf.open(PAYLOAD) as fh:
                r = _ProgressReader(fh, (lambda d: progress("hash", d, total)) if progress else None)
                while block := r.read(1024 * 1024):
                    h.update(block)
            payload_ok = h.hexdigest() == meta["payload"]["sha256"]
        stamps: list[StampResult] = []
        errors: list[str] = []
        digests = {
            "payload": bytes.fromhex(meta["payload"]["sha256"]),
            "commitment": bytes.fromhex(meta["commitment"]["sha256"]),
        }
        for ts in meta.get("timestamps", []):
            try:
                der = zf.read(ts["file"])
                info = tsamod.verify_response(der, digests[ts["covers"]], anchors=anchors,
                                              require_chain=False)
                stamps.append(StampResult(ts["covers"], ts["file"], ts.get("tsa_name", ""),
                                          ts.get("tsa_url", ""), info))
            except (KeyError, tsamod.TsaError) as exc:
                errors.append(f"{ts.get('file', '?')}: {exc}")
    return ContainerInfo(
        path=path, meta=meta, round=round_no,
        unlock_time=QUICKNET.round_time(round_no),
        target_time=_parse_iso(meta["target_time_utc"]),
        stamps=stamps, stamp_errors=errors, payload_hash_ok=payload_ok,
    )


def check_ready(info: ContainerInfo, drand: DrandClient) -> int:
    """Wirft NotYet, wenn die Zielrunde laut drand noch nicht erreicht ist.
    Die lokale Uhr wird dafür nicht verwendet."""
    latest = drand.latest_round()
    if latest < info.round:
        remaining = (info.round - latest) * QUICKNET.period
        raise NotYet(info.round, latest, info.unlock_time, remaining)
    return latest


# --------------------------------------------------------------------------
# Entschlüsseln
# --------------------------------------------------------------------------

def decrypt_file(path: Path, out_dir: Path, *, drand: DrandClient, tle: Tle,
                 anchors=None, progress: Progress | None = None,
                 cancel: threading.Event | None = None) -> DecryptResult:
    path = Path(path)
    out_dir = Path(out_dir)
    info = inspect(path, anchors=anchors, check_payload_hash=False)
    drand.verify_chain()
    check_ready(info, drand)
    tle.network = drand.active_relay or tle.network
    tle.chain_hash = info.meta["drand"]["chain_hash"]

    with _open(path) as zf:
        try:
            secret = json.loads(tle.decrypt_bytes(zf.read(SECRET)).decode("utf-8"))
            salt = bytes.fromhex(secret["salt"])
        except TooEarly:
            check_ready(info, drand)
            raise
        except (ValueError, KeyError) as exc:
            raise IntegrityError(f"secret.age fehlerhaft: {exc}") from exc

        original = safe_filename(secret.get("filename", ""))
        target = unique_path(out_dir / original)
        part = target.with_name(target.name + ".part")
        h_payload = hashlib.sha256()
        h_plain = hashlib.sha256()
        h_commit = hashlib.sha256(salt)
        size = 0

        def count(b: bytes) -> None:
            nonlocal size
            size += len(b)

        total = zf.getinfo(PAYLOAD).file_size
        try:
            with zf.open(PAYLOAD) as fin, open(part, "wb") as fout:
                tle.run_stream(
                    tle.decrypt_args(), fin, fout,
                    in_hooks=[h_payload.update],
                    out_hooks=[h_plain.update, h_commit.update, count],
                    progress=(lambda d: progress("decrypt", d, total)) if progress else None,
                    cancel=cancel,
                )
            if h_payload.hexdigest() != info.meta["payload"]["sha256"]:
                raise IntegrityError("SHA-256 des Chiffrats weicht von den Metadaten ab")
            if h_plain.hexdigest() != secret.get("sha256"):
                raise IntegrityError("SHA-256 des Klartexts weicht ab")
            if h_commit.hexdigest() != info.meta["commitment"]["sha256"]:
                raise IntegrityError("Commitment passt nicht zum Klartext")
            os.replace(part, target)
        except BaseException:
            try:
                part.unlink()
            except FileNotFoundError:
                pass
            raise
    info.payload_hash_ok = True
    return DecryptResult(target, original, size, info)
