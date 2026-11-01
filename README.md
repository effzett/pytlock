# pytlock

Zeitschloss für Dateien: pytlock verschlüsselt eine Datei so, dass sie erst ab
einem gewählten Zeitpunkt wieder entschlüsselt werden kann. Die Einlieferungszeit
wird über RFC-3161-Zeitstempel belegt.

- **Zeitschloss ohne lokalen Schlüssel:** [drand/tlock](https://github.com/drand/tlock)
  über das quicknet-Netz der League of Entropy. Den Entschlüsselungsschlüssel
  gibt es vor dem Zielzeitpunkt nirgends. Die Systemuhr spielt keine Rolle.
- **Offenes Format:** Die `.pytlock`-Datei ist ein ZIP. Der Inhalt lässt sich
  auch ohne pytlock mit `tle` entschlüsseln, die Zeitstempel lassen sich mit
  `openssl ts -verify` prüfen ([docs/FORMAT.md](docs/FORMAT.md)).
- **Einlieferungsnachweis:** FreeTSA, ersatzweise DigiCert. Gestempelt werden
  das Chiffrat und ein gesalzenes Klartext-Commitment.

Hintergrund, Entscheidungen und Bedrohungsmodell: [docs/DESIGN.md](docs/DESIGN.md).

## Installation (Release)

Unter [Releases](../../releases):

- `pytlock-macos-arm64.zip` – macOS mit Apple Silicon
- `pytlock-windows-x64.zip` – Windows 10/11

Die Programme sind **nicht signiert**.
- macOS: Gatekeeper blockiert den ersten Start. Abhilfe: Rechtsklick → Öffnen,
  oder `xattr -dr com.apple.quarantine /Applications/pytlock.app`.
- Windows: SmartScreen zeigt eine Warnung. Weiter über „Weitere Informationen“
  → „Trotzdem ausführen“.

Verschlüsseln und Entschlüsseln brauchen eine Internetverbindung.

## Entwicklung

Python 3.12, PyCharm.

```sh
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

`tle` (Go-Referenzimplementierung) nach `vendor/tle/` holen. Weder Go noch
Adminrechte sind nötig. Das offizielle Release v1.2.0 gegen `checksums.txt`
prüfen:

```sh
mkdir -p vendor/tle && cd vendor/tle
B=https://github.com/drand/tlock/releases/download/v1.2.0
curl -LO $B/checksums.txt -LO $B/tlock_1.2.0_darwin_arm64.tar.gz
grep darwin_arm64 checksums.txt | shasum -a 256 -c
tar -xzf tlock_1.2.0_darwin_arm64.tar.gz tle LICENSE-MIT LICENSE-APACHE
cd ../..
vendor/tle/tle -m
```

Alternativ mit Go: `GOBIN="$PWD/vendor/tle" go install github.com/drand/tlock/cmd/tle@v1.2.0`

Tests und Start:

```sh
pytest
pytest -m live
python -m pytlock
pytlock encrypt brief.txt --at 2027-01-01T12:00
pytlock info pytlock-20270101-1100Z.pytlock
pytlock decrypt pytlock-20270101-1100Z.pytlock
```

`pytest` läuft ohne Netz (mit Fake-tle und Test-TSA), `pytest -m live` gegen das
echte drand-Netz, echte TSAs und das echte tle.

`tle` wird in dieser Reihenfolge gesucht: `PYTLOCK_TLE`, App-Bundle,
`vendor/tle/`, `PATH`.

FreeTSA-Wurzelzertifikat einmalig holen, Fingerabdruck mit freetsa.org
vergleichen und committen:

```sh
python scripts/fetch_tsa_certs.py
```

Ohne diese Datei lässt sich die Kette von FreeTSA nicht prüfen. pytlock weicht
dann automatisch auf DigiCert aus, dessen Wurzel im certifi-Bundle enthalten ist.

## Release

```sh
git tag v0.1.0 && git push origin v0.1.0
```

GitHub Actions baut `tle` aus den Quellen, führt Unit- und Live-Tests aus,
paketiert mit PyInstaller für macOS arm64 und Windows x64 und veröffentlicht
ein Release mit `SHA256SUMS.txt`.

## Einstellungen

Optional in `~/.pytlock.json`:

```json
{
  "relays": ["https://api.drand.sh/", "https://drand.cloudflare.com/"],
  "tsas": [
    {"name": "FreeTSA", "url": "https://freetsa.org/tsr"},
    {"name": "DigiCert", "url": "http://timestamp.digicert.com"}
  ]
}
```

## Lizenz

MIT. Mitgelieferte Drittsoftware: [packaging/THIRD_PARTY.txt](packaging/THIRD_PARTY.txt).
