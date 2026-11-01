"""drand-Anbindung: gepinnte quicknet-Parameter, Rundenarithmetik, HTTP-Client.

Die Parameter von quicknet sind fest im Programm hinterlegt und werden bei
jedem Netzzugriff gegen die /info-Antwort des Relays geprüft. Ein Relay, das
einen anderen öffentlichen Schlüssel ausliefert, wird abgelehnt.

Quelle der Werte: drand/tlock, networks/fixed/fixed_test.go (Tag v1.2.0+).
"""
from __future__ import annotations

import json
import math
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

import certifi


@dataclass(frozen=True)
class ChainInfo:
    chain_hash: str
    public_key: str
    period: int
    genesis_time: int
    scheme: str
    beacon_id: str

    # -- Rundenarithmetik ---------------------------------------------------
    # Runde r wird zum Zeitpunkt genesis + (r - 1) * period veröffentlicht.

    def round_time(self, round_no: int) -> datetime:
        if round_no < 1:
            raise ValueError("Runde muss >= 1 sein")
        ts = self.genesis_time + (round_no - 1) * self.period
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    def round_at(self, when: datetime) -> int:
        """Erste Runde, die zum Zeitpunkt *when* oder danach veröffentlicht wird."""
        if when.tzinfo is None:
            raise ValueError("Zeitpunkt muss zeitzonenbehaftet sein")
        delta = when.timestamp() - self.genesis_time
        if delta <= 0:
            return 1
        return math.ceil(delta / self.period) + 1


QUICKNET = ChainInfo(
    chain_hash="52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    public_key=(
        "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c"
        "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb"
        "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
    ),
    period=3,
    genesis_time=1692803367,
    scheme="bls-unchained-g1-rfc9380",
    beacon_id="quicknet",
)

DEFAULT_RELAYS = (
    "https://api.drand.sh/",
    "https://drand.cloudflare.com/",
)


class DrandError(Exception):
    """Netz- oder Protokollfehler bei drand."""


class ChainMismatch(DrandError):
    """Relay liefert andere Kettenparameter als gepinnt."""


def _ssl_context() -> ssl.SSLContext:
    # python.org-Python auf macOS hat ohne "Install Certificates" keine CA-Liste.
    return ssl.create_default_context(cafile=certifi.where())


class DrandClient:
    def __init__(self, relays: tuple[str, ...] | list[str] = DEFAULT_RELAYS,
                 chain: ChainInfo = QUICKNET, timeout: float = 15.0):
        self.relays = [r if r.endswith("/") else r + "/" for r in relays]
        self.chain = chain
        self.timeout = timeout
        self.active_relay: str | None = None

    def _get_json(self, path: str) -> dict:
        errors = []
        for relay in self.relays:
            url = f"{relay}{self.chain.chain_hash}/{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "pytlock"})
                with urllib.request.urlopen(req, timeout=self.timeout,
                                            context=_ssl_context()) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                self.active_relay = relay
                return data
            except (urllib.error.URLError, OSError, ValueError) as exc:
                errors.append(f"{relay}: {exc}")
        raise DrandError("Kein drand-Relay erreichbar: " + "; ".join(errors))

    def verify_chain(self) -> ChainInfo:
        """Holt /info und prüft es gegen die gepinnten Parameter."""
        info = self._get_json("info")
        expected = {
            "public_key": self.chain.public_key,
            "period": self.chain.period,
            "genesis_time": self.chain.genesis_time,
            "hash": self.chain.chain_hash,
            "schemeID": self.chain.scheme,
        }
        for key, want in expected.items():
            got = info.get(key)
            if got is None and key == "hash":
                got = info.get("chain_hash")
            if got is None and key == "schemeID":
                got = info.get("scheme")
            if got != want:
                raise ChainMismatch(f"drand-Info weicht ab bei {key!r}: {got!r} != {want!r}")
        return self.chain

    def latest_round(self) -> int:
        data = self._get_json("public/latest")
        try:
            return int(data["round"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DrandError(f"Unerwartete Antwort von drand: {data!r}") from exc
