"""Holt je einen Zeitstempel von jeder konfigurierten TSA, speichert die
Antworten unter diag/ und zeigt, welche Zertifikate im Token stecken."""
import hashlib
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from asn1crypto import tsp  # noqa: E402

from pytlock import tsa  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "diag"
OUT.mkdir(exist_ok=True)
digest = hashlib.sha256(b"pytlock diag").digest()

for t in tsa.DEFAULT_TSAS:
    host = t["url"].split("/")[2]
    print(f"== {t['name']} ({t['url']})")
    try:
        print("   DNS:", sorted({a[4][0] for a in socket.getaddrinfo(host, None)}))
    except OSError as e:
        print("   DNS-Fehler:", e)
        continue
    body, nonce = tsa.build_request(digest)
    t0 = time.time()
    try:
        der = tsa.http_post(t["url"], body)
    except tsa.TsaError as e:
        print("   HTTP-Fehler:", e)
        continue
    print(f"   Antwort {len(der)} Bytes in {time.time() - t0:.1f}s")
    (OUT / f"{t['name']}.tsr").write_bytes(der)
    resp = tsp.TimeStampResp.load(der)
    sd = resp["time_stamp_token"]["content"]
    for c in sd["certificates"] or []:
        c = c.chosen
        print("   Zertifikat:", c.subject.human_friendly, "| Aussteller:", c.issuer.human_friendly)
    try:
        info = tsa.verify_response(der, digest, nonce=nonce)
        print("   OK, Kette bis:", info.anchor_subject)
    except tsa.TsaError as e:
        print("   Prüfung:", e)
