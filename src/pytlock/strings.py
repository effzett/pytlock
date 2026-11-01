"""Alle Oberflächentexte (Deutsch). Für eine Übersetzung diese Datei ersetzen."""

APP_TITLE = "pytlock – Zeitschloss für Dateien"
TAB_ENCRYPT = "Verschlüsseln"
TAB_DECRYPT = "Entschlüsseln"

LBL_SOURCE = "Datei:"
LBL_TARGET = "Entschlüsselbar ab:"
LBL_TARGET_UTC = "entspricht {utc} UTC"
LBL_OUTPUT = "Ausgabe:"
LBL_CONTAINER = "pytlock-Datei:"
LBL_OUTDIR = "Zielordner:"
DROP_HINT = "Datei hierher ziehen oder „Auswählen …“ klicken"

BTN_CHOOSE = "Auswählen …"
BTN_ENCRYPT = "Zeitgesperrt verschlüsseln"
BTN_DECRYPT = "Entschlüsseln"
BTN_CHECK = "Prüfen"
BTN_CANCEL = "Abbrechen"

PH_ENCRYPT = "Verschlüssele …"
PH_DECRYPT = "Entschlüssele …"
PH_TIMESTAMP = "Hole Zeitstempel …"
PH_HASH = "Prüfe Chiffrat …"
PH_CONNECT = "Verbinde mit drand …"

MSG_DONE_ENCRYPT = (
    "Fertig.\n\nDatei: {output}\nEntschlüsselbar ab: {unlock} (drand-Runde {round})\n"
    "Einlieferung bestätigt: {submitted} ({tsa})"
)
MSG_DONE_DECRYPT = "Entschlüsselt nach:\n{output}\n\nGröße: {size} Bytes"
MSG_NOT_YET = (
    "Noch gesperrt.\n\nEntschlüsselbar ab {unlock}.\n"
    "Restzeit laut drand-Netz: {remaining}"
)
MSG_TARGET_PAST = "Der gewählte Zeitpunkt liegt in der Vergangenheit."
MSG_NO_NETWORK = (
    "Keine Verbindung.\n\nZum Verschlüsseln (Zeitstempel, drand) und Entschlüsseln "
    "wird eine Internetverbindung benötigt.\n\nDetails: {detail}"
)
MSG_TSA = (
    "Zeitstempel konnte nicht eingeholt werden.\n\nDetails: {detail}"
)
MSG_NO_TLE = "Das Hilfsprogramm „tle“ fehlt.\n\n{detail}"
MSG_ERROR = "Fehler:\n\n{detail}"
MSG_CANCELLED = "Abgebrochen. Es wurde keine Ausgabedatei angelegt."
MSG_SOURCE_WARNING = (
    "Hinweis: Die Originaldatei bleibt unverändert liegen. Wer sie vor dem Zielzeitpunkt "
    "nicht lesen können soll, muss sie selbst entfernen – auf SSDs, in APFS-Snapshots "
    "und Backups ist das nicht zuverlässig möglich."
)

INFO_TEMPLATE = (
    "Entschlüsselbar ab: {unlock}  (drand-Runde {round})\n"
    "Eingeliefert: {submitted}\n"
    "Zeitstempel: {stamps}\n"
    "Chiffrat unverändert: {payload_ok}"
)
STAMP_OK = "{covers}: {time} ({tsa}, Kette {chain})"
CHAIN_OK = "geprüft"
CHAIN_NOK = "nicht geprüft"
YES = "ja"
NO = "NEIN"
UNKNOWN = "–"


def fmt_duration(seconds: int) -> str:
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d} Tag{'e' if d != 1 else ''}")
    if h or d:
        parts.append(f"{h} Std.")
    if m or h or d:
        parts.append(f"{m} Min.")
    parts.append(f"{s} Sek.")
    return " ".join(parts)
