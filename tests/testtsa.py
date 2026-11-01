"""Minimale RFC-3161-TSA für Tests (nur Testschlüssel aus tests/fixtures)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from asn1crypto import algos, cms, core, tsp, x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

FIX = Path(__file__).parent / "fixtures"


class TestTSA:
    __test__ = False

    def __init__(self, gen_time: datetime | None = None, tamper: str | None = None):
        self.key = serialization.load_pem_private_key((FIX / "test-tsa.key").read_bytes(), None)
        self.cert_pem = (FIX / "test-tsa.pem").read_bytes()
        self.cert = x509.load_pem_x509_certificate(self.cert_pem)
        self.ca = x509.load_pem_x509_certificate((FIX / "test-ca.pem").read_bytes())
        self.gen_time = gen_time
        self.tamper = tamper
        self.serial = 1000
        self.requests: list[str] = []

    @property
    def anchors(self) -> list[x509.Certificate]:
        return [self.ca]

    def post(self, url: str, body: bytes) -> bytes:
        self.requests.append(url)
        req = tsp.TimeStampReq.load(body)
        return self.reply(req)

    def reply(self, req: tsp.TimeStampReq) -> bytes:
        self.serial += 1
        gen_time = self.gen_time or datetime.now(timezone.utc).replace(microsecond=0)
        tst = tsp.TSTInfo({
            "version": 1,
            "policy": "1.2.3.4.1",
            "message_imprint": req["message_imprint"],
            "serial_number": self.serial,
            "gen_time": gen_time,
            "nonce": req["nonce"].native,
        })
        tst_der = tst.dump()
        cert_der = self.cert.public_bytes(serialization.Encoding.DER)
        a_cert = ax509.Certificate.load(cert_der)
        signed_attrs = cms.CMSAttributes([
            {"type": "content_type", "values": ["tst_info"]},
            {"type": "message_digest", "values": [hashlib.sha256(tst_der).digest()]},
            {"type": "signing_certificate_v2", "values": [{
                "certs": [{"cert_hash": hashlib.sha256(cert_der).digest()}],
            }]},
        ])
        to_sign = signed_attrs.dump()
        if self.tamper == "signature":
            to_sign = to_sign[:-1] + bytes([to_sign[-1] ^ 1])
        signature = self.key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
        sd = cms.SignedData({
            "version": "v3",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
            "encap_content_info": {
                "content_type": "tst_info",
                "content": core.ParsableOctetString(tst_der),
            },
            "certificates": [a_cert],
            "signer_infos": [{
                "version": "v1",
                "sid": cms.SignerIdentifier({"issuer_and_serial_number": {
                    "issuer": a_cert.issuer, "serial_number": a_cert.serial_number}}),
                "digest_algorithm": {"algorithm": "sha256"},
                "signed_attrs": signed_attrs,
                "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                "signature": signature,
            }],
        })
        resp = tsp.TimeStampResp({
            "status": {"status": "granted"},
            "time_stamp_token": {"content_type": "signed_data", "content": sd},
        })
        return resp.dump()
