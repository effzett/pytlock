# pytlock-Containerformat, Version 1

Eine `.pytlock`-Datei ist ein gewöhnliches ZIP-Archiv (alle Einträge
unkomprimiert, ZIP64 erlaubt). Sie lässt sich mit jedem Entpacker öffnen. Alle
Bestandteile sind mit Standardwerkzeugen prüfbar, pytlock selbst wird dafür
nicht gebraucht.

| Eintrag          | Inhalt |
|------------------|--------|
| `pytlock.json`   | öffentliche Metadaten (UTF-8-JSON, siehe unten) |
| `payload.age`    | tlock-Chiffrat der Datei im age-Format, erzeugt mit `tle -e -r <runde>` |
| `secret.age`     | tlock-Chiffrat (gleiche Runde) eines JSON-Objekts mit Salt, Originaldateiname, Größe und SHA-256 des Klartexts |
| `payload.tsr`    | RFC-3161-`TimeStampResp` über `SHA-256(payload.age)` |
| `commitment.tsr` | RFC-3161-`TimeStampResp` über `SHA-256(salt ‖ Klartext)` |
| `LIESMICH.txt`   | Kurzanleitung zur externen Prüfung |

## pytlock.json

```json
{
  "format": "pytlock",
  "version": 1,
  "created_by": "pytlock 0.1.0",
  "tle_version": "v1.2.0",
  "target_time_utc": "2027-01-01T11:00:00Z",
  "drand": {
    "beacon_id": "quicknet",
    "chain_hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    "scheme": "bls-unchained-g1-rfc9380",
    "genesis_time": 1692803367,
    "period": 3,
    "round": 35332612,
    "round_time_utc": "2027-01-01T11:00:00Z",
    "relay": "https://api.drand.sh/"
  },
  "payload":    { "file": "payload.age", "size": 1234, "sha256": "<hex>" },
  "secret":     { "file": "secret.age" },
  "commitment": { "algorithm": "sha256(salt || plaintext)", "sha256": "<hex>" },
  "timestamps": [
    { "covers": "payload",    "file": "payload.tsr",    "tsa_name": "FreeTSA",
      "tsa_url": "https://freetsa.org/tsr", "gen_time_utc": "…", "serial": "…", "tsa_subject": "…" },
    { "covers": "commitment", "file": "commitment.tsr", "…": "…" }
  ]
}
```

(Werte beispielhaft.)

- `target_time_utc`: vom Nutzer gewählter Zeitpunkt.
- `drand.round`: erste quicknet-Runde, die zu diesem Zeitpunkt oder danach veröffentlicht wird.
  Es gilt `round_time = genesis_time + (round − 1) · period`.
- `gen_time_utc` dient nur der Bequemlichkeit. Maßgeblich ist das `genTime` im signierten Token.

## secret.age (Klartext nach Entschlüsselung)

```json
{ "version": 1, "salt": "<64 hex>", "filename": "brief.txt", "size": 1234, "sha256": "<hex>" }
```

## Warum Salt und Commitment?

Ein offener `SHA-256(Klartext)` würde das Zeitschloss bei kurzen oder
erratbaren Inhalten aushebeln: Wer den Container hat, könnte Kandidaten wie
„ja“, „nein“ oder eine Zahl hashen und vergleichen. Deshalb wird nur
`SHA-256(salt ‖ Klartext)` gestempelt und offen gespeichert. Das 32-Byte-Salt
liegt zeitgesperrt in `secret.age`. Aus demselben Grund steht auch der
Originaldateiname nur dort.

Offen bleiben weiterhin die **Größe** (das Chiffrat ist nur wenige hundert
Bytes größer als der Klartext) und der **Zielzeitpunkt**.

## Externe Prüfung

```sh
unzip datei.pytlock -d x && cd x

# 1. Entschlüsseln (ab Zielrunde)
tle -d -o klartext payload.age

# 2. Einlieferungszeit lesen und Stempel über das Chiffrat prüfen
openssl ts -reply -in payload.tsr -text
openssl ts -verify -in payload.tsr -data payload.age -CAfile <TSA-Wurzel.pem>

# 3. Stempel über den Klartext prüfen
tle -d secret.age                                    # zeigt "salt"
(printf '%s' <salt-hex> | xxd -r -p; cat klartext) > commit.bin
openssl ts -verify -in commitment.tsr -data commit.bin -CAfile <TSA-Wurzel.pem>
```

TSA-Wurzeln: FreeTSA `https://freetsa.org/files/cacert.pem`, DigiCert
„DigiCert Trusted Root G4“ (im System- bzw. Mozilla-Zertifikatsspeicher).

## Versionierung

Leser lehnen unbekannte `version`-Werte ab. Neue Felder ohne geänderte Semantik
dürfen hinzukommen. Wer Felder entfernt oder ihre Bedeutung ändert, muss die
Version erhöhen.
