# Entwurfsentscheidungen

## Zeitschloss: drand/tlock, quicknet

Die Datei wird per Identity-Based Encryption auf eine künftige drand-Runde
verschlüsselt (tlock, Gailly/Melissaris/Romailler, IACR ePrint 2023/189). Den
„privaten Schlüssel“ der Runde N bildet die BLS-Threshold-Signatur des
drand-Netzes über N. Sie entsteht erst zur Runde N. Vorher existiert der
Schlüssel nirgendwo: nicht lokal, nicht im Programm, nicht bei drand. Die
lokale Uhr wird nirgends als Schutz verwendet. Für die Restzeitanzeige und die
Prüfung, ob ein Zielzeitpunkt in der Zukunft liegt, nutzt pytlock die aktuelle
Rundennummer vom drand-Netz.

Gepinnt sind Chain-Hash, öffentlicher Schlüssel, Genesis, Periode und Schema
von quicknet (Quelle: drand/tlock `networks/fixed/fixed_test.go`). Bei jedem
Netzzugriff werden sie gegen `/info` des Relays geprüft. `tle` bekommt
zusätzlich den Chain-Hash mit `-c` und prüft den öffentlichen Schlüssel
selbst.

## Python-Anbindung: Go-CLI `tle` statt bittensor-drand

Geprüft am 01.11.2026:

- **bittensor-drand** verwendet ein eigenes AES-GCM-Format mit angehängter
  Rundennummer (Suffix `AES_GCM_`), kein age/tlock. Es ist mit `tle` nicht
  austauschbar. Das Repository ist archiviert, die Funktion ist in
  `bittensor-core` aufgegangen, das auf die Bittensor-Chain ausgerichtet ist
  und keine Windows-Wheels nennt. → verworfen.
- **tlock_age (Rust)** ist formatkompatibel, hat aber keine Python-Bindings,
  ist laut eigener Angabe nicht auditiert und wurde zuletzt 2024 gepusht.
  → verworfen.
- **tle (drand/tlock, Go)** ist die Referenzimplementierung, erzeugt
  age-Format und ist ein statisches Binary ohne CGO für macOS und Windows.
  → gewählt, Version `v1.2.0`. In CI wird es per `go install …@v1.2.0` aus
  den Quellen gebaut. Die Modulintegrität sichert `sum.golang.org`.

Datenfluss: Python liest die Quelldatei und hasht sie. Die Daten gehen über
stdin an `tle`, das Chiffrat kommt über stdout zurück und wird direkt ins ZIP
gestreamt. Es entstehen keine Klartext-Zwischendateien. Der Speicherbedarf
bleibt unabhängig von der Dateigröße.

## Einlieferungszeitstempel: RFC 3161

Standard ist FreeTSA, Fallback DigiCert (beide konfigurierbar in
`~/.pytlock.json`). Pro Container werden zwei Tokens geholt: einer über das
Chiffrat und einer über das gesalzene Klartext-Commitment (Begründung in
FORMAT.md). pytlock prüft jedes Token vollständig:

- Status, MessageImprint und Nonce
- CMS-Signatur über die signierten Attribute
- messageDigest und ESS-signingCertificate(v2)
- EKU timeStamping
- Gültigkeit zum Stempelzeitpunkt
- Kette bis zu einem Vertrauensanker (gebündelte PEMs plus certifi)

Die Prüflogik ist in beide Richtungen gegen `openssl ts` getestet.

## Bedrohungsmodell

Geschützt wird gegen den Nutzer selbst und gegen Dritte mit Dateizugriff vor
dem Zielzeitpunkt. Folgende Annahmen und Grenzen gelten:

- **Vertrauen in drand:** Wenn mindestens so viele League-of-Entropy-Knoten
  kolludieren, wie der Threshold verlangt, können sie die Rundensignatur
  vorzeitig berechnen.
- **Klartext beim Verschlüsseln:** Die Originaldatei bleibt liegen. Sicheres
  Löschen ist auf SSDs, APFS-Snapshots und Backups nicht zuverlässig. Die GUI
  weist darauf hin.
- **Arbeitsspeicher:** Während des Verschlüsselns liegen Klartextblöcke und
  das Salt im RAM, möglicherweise auch im Swap. Python kann Speicher nicht
  verlässlich überschreiben.
- **Nach dem Zielzeitpunkt:** Die Rundensignatur ist öffentlich und bleibt es.
  Ab dann ist der Container nur so vertraulich wie sein Speicherort.
- **Metadaten:** Größe und Zielzeitpunkt sind offen.
- **TSA:** Die Zeitstempel belegen, dass genau diese Daten spätestens zur
  genTime existierten. Sie belegen nicht, wer sie eingeliefert hat.

## Packaging

PyInstaller, onedir, mit `tle` unter `bin/`. macOS: `.app` für arm64.
Windows: Ordner mit `pytlock.exe`. Vorerst ohne Signatur. Signierung und
Notarisierung lassen sich später über GitHub Secrets nachrüsten.
