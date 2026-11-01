"""Lädt die FreeTSA-Zertifikate nach src/pytlock/data/tsa/ und zeigt die
SHA-256-Werte an. Vergleichen mit den zwei SHA256-Werten auf
https://www.freetsa.org/index_de.php (Abschnitt Zertifikate: tsa.crt und cacert.pem).
Es genügt, wenn EINER der beiden ausgegebenen Werte passt (Stand 11/2026: der
Datei-Hash von cacert.pem).

Nur die Wurzel-CA wird als Vertrauensanker gebündelt. Das TSA-Zertifikat selbst
liefert FreeTSA in jedem Token mit; pytlock prüft es gegen die Wurzel.

DigiCert braucht keinen eigenen Eintrag: dessen Wurzel steckt im certifi-Bundle.
"""
import hashlib
import ssl
import sys
import urllib.request
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes

DEST = Path(__file__).resolve().parents[1] / "src" / "pytlock" / "data" / "tsa"
FILES = {
    "freetsa-cacert.pem": "https://freetsa.org/files/cacert.pem",
}


def main() -> int:
    ctx = ssl.create_default_context(cafile=certifi.where())
    DEST.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        data = urllib.request.urlopen(url, context=ctx, timeout=30).read()
        cert = (x509.load_pem_x509_certificate(data) if b"BEGIN" in data
                else x509.load_der_x509_certificate(data))
        (DEST / name).write_bytes(data)
        print(f"{name}: {cert.subject.rfc4514_string()}")
        print(f"  gültig bis {cert.not_valid_after_utc:%Y-%m-%d}")
        print(f"  SHA-256 der Datei:         {hashlib.sha256(data).hexdigest()}")
        print(f"  SHA-256 des Zertifikats:   {cert.fingerprint(hashes.SHA256()).hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
