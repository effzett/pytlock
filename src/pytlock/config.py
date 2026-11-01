"""Einstellungen. Optional überschreibbar per JSON-Datei ~/.pytlock.json:

    {"relays": ["https://api.drand.sh/"],
     "tsas": [{"name": "FreeTSA", "url": "https://freetsa.org/tsr"}]}
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .drand import DEFAULT_RELAYS, DrandClient
from .tle import Tle
from .tsa import DEFAULT_TSAS, http_post


def config_path() -> Path:
    return Path(os.environ.get("PYTLOCK_CONFIG", Path.home() / ".pytlock.json"))


@dataclass
class Settings:
    relays: list[str] = field(default_factory=lambda: list(DEFAULT_RELAYS))
    tsas: list[dict] = field(default_factory=lambda: [dict(t) for t in DEFAULT_TSAS])
    post: object = http_post          # austauschbar für Tests
    anchors: list | None = None       # None = gebündelte Anker + certifi

    @classmethod
    def load(cls) -> "Settings":
        s = cls()
        p = config_path()
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            if data.get("relays"):
                s.relays = list(data["relays"])
            if data.get("tsas"):
                s.tsas = [dict(t) for t in data["tsas"]]
        return s

    def drand(self) -> DrandClient:
        return DrandClient(self.relays)

    def tle(self) -> Tle:
        return Tle(network=self.relays[0])
