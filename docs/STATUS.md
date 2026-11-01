# Projektstatus pytlock

Stand: 01.11.2026, 16:40

## Release v0.1.0

- Tag `v0.1.0` zeigt auf Commit `9024635`. Der erste Tag auf `3d98f2c` wurde
  gelöscht und neu gesetzt.
- CI #2 und Release #2 sind grün. Das Release enthält
  `pytlock-macos-arm64.zip`, `pytlock-windows-x64.zip` und `SHA256SUMS.txt`.

### Behoben: Windows-Unit-Test (Release #1 rot)

- `tests/test_tsa.py::test_accepts_openssl_generated_token` schrieb Windows-Pfade
  mit Backslashes in `ts.cnf`. Der OpenSSL-Konfigurationsparser wertet `\` als
  Escape-Zeichen, dadurch wurde der Zertifikatspfad zerstört.
- Lösung: Die Pfade werden mit `.as_posix()` geschrieben (Commit `9024635`).
- Der Fehler lag nur im Test. Die Programmlogik war nicht betroffen.

## Offen: macOS-Release-Build startet nicht

Symptom: Das Icon im Dock hüpft, es erscheint kein Fenster und keine
Fehlermeldung. Das gilt auch für den Start im Terminal über
`pytlock.app/Contents/MacOS/pytlock`.

Befunde (Rohdaten in `diag/`, das per .gitignore ausgeschlossen ist):

- `sample` (diag/sample.txt): Der Prozess steht dauerhaft bei `_dyld_start`
  und belegt 96 KB Speicher. Es wurde noch kein Code und keine Bibliothek
  geladen. Ursache ist also weder Python, Qt noch der eigene Code.
- `codesign` (diag/codesign.txt): Die Signatur ist „valid on disk“ und
  erfüllt die Designated Requirement (ad-hoc). `spctl` meldet „rejected“,
  was ohne Notarisierung erwartbar ist. Das Quarantäne-Flag ist entfernt,
  übrig ist nur `com.apple.provenance`.
- Bundle-Analyse des Release-ZIPs: Die Struktur ist vollständig, die
  Symlinks sind erhalten (ditto), Info.plist ist korrekt. Hauptprogramm,
  Python und tle sind arm64 und ad-hoc-signiert.
- Start aus dem Quellcode (`python packaging/launch_gui.py`): funktioniert;
  Frank hat die Anwendung damit auf macOS getestet (16:49), läuft.
- Funktionstest aus dem Quellcode auf macOS bestanden: Datei verschlüsselt,
  Entschlüsselung vor der Zielrunde zeigt die Restzeit-Meldung, nach Ablauf
  wurde erfolgreich entschlüsselt.
- Lokaler PyInstaller-Build (`pyinstaller packaging/pytlock.spec`):
  startet normal.
- macOS 27.2. Das Konto hat keine Admin- bzw. sudo-Rechte, daher ist kein
  Systemlog (syspolicyd/amfid) verfügbar.

Ergebnis des Unterscheidungstests (16:53): Der CI-Build wurde per curl
geladen, ohne Browser. `xattr -l` zeigt keine Attribute, die App startet
normal.

**Ursache geklärt:** Der CI-Build ist in Ordnung. macOS 27 hält den Start
eines per Browser heruntergeladenen, nicht notarisierten Bundles an (Herkunft,
Provenance). Auch „Dennoch öffnen“ und `xattr -dr com.apple.quarantine` helfen
nicht, weil `com.apple.provenance` bestehen bleibt.

- Workaround für Nutzer: Download per curl, beschrieben in
  packaging/LIESMICH-macOS.txt.
- Dauerhafte Lösung: Developer-ID-Signierung und Notarisierung im
  Release-Workflow. Voraussetzung ist das Apple Developer Program
  (99 US-$/Jahr). Zertifikat und Notary-Zugang kommen als GitHub Secrets
  hinzu. Offen ist, ob das gewünscht ist.

## Weitere offene Punkte

- Windows-Build: Praxistest steht noch aus (SmartScreen, Start, ein
  Durchlauf Verschlüsseln und Entschlüsseln).
- GUI: Das Dateifeld ist zu schmal, der Platzhalter wird abgeschnitten.
- CI: Die Actions-Warnung „Node.js 20 deprecated“ betrifft checkout@v4,
  setup-go@v5 und setup-python@v5. Sie stört nicht, die Versionen sollten
  aber gelegentlich angehoben werden.
- Paketierung macOS: Das ZIP enthält ein weiteres ZIP (`pytlock.app.zip`).
  Das ist gewollt, weil ditto die Symlinks erhält. Kann man dokumentieren
  oder auf ein einziges ditto-ZIP umstellen.
