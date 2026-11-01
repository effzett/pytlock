import hashlib
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509

from pytlock import tsa as tsamod
from testtsa import FIX, TestTSA

DIGEST = hashlib.sha256(b"hallo").digest()


def test_valid_token(tsa: TestTSA):
    der, entry, info = tsamod.request_timestamp(DIGEST, post=tsa.post, anchors=tsa.anchors)
    assert info.chain_verified
    assert info.hashed_message == DIGEST
    assert entry["name"] == "FreeTSA"


def test_wrong_digest(tsa: TestTSA):
    der, _, _ = tsamod.request_timestamp(DIGEST, post=tsa.post, anchors=tsa.anchors)
    with pytest.raises(tsamod.TsaVerifyError, match="Hash"):
        tsamod.verify_response(der, b"\x00" * 32, anchors=tsa.anchors)


def test_wrong_nonce_rejected(tsa: TestTSA):
    body, nonce = tsamod.build_request(DIGEST)
    der = tsa.post("x", body)
    with pytest.raises(tsamod.TsaVerifyError, match="Nonce"):
        tsamod.verify_response(der, DIGEST, nonce=nonce + 2, anchors=tsa.anchors)


def test_tampered_signature_rejected():
    t = TestTSA(tamper="signature")
    body, nonce = tsamod.build_request(DIGEST)
    der = t.post("x", body)
    with pytest.raises(tsamod.TsaVerifyError, match="Signatur"):
        tsamod.verify_response(der, DIGEST, nonce=nonce, anchors=t.anchors)


def test_untrusted_anchor():
    t = TestTSA()
    body, nonce = tsamod.build_request(DIGEST)
    der = t.post("x", body)
    other = x509.load_pem_x509_certificates((FIX / "other-ca.pem").read_bytes())
    with pytest.raises(tsamod.TsaVerifyError, match="Vertrauensanker"):
        tsamod.verify_response(der, DIGEST, anchors=other)
    info = tsamod.verify_response(der, DIGEST, anchors=other, require_chain=False)
    assert not info.chain_verified and info.warnings


def test_fallback_to_second_tsa():
    t = TestTSA()

    def post(url, body):
        if "first" in url:
            raise tsamod.TsaError("nicht erreichbar")
        return t.post(url, body)

    tsas = [{"name": "A", "url": "https://first.invalid"}, {"name": "B", "url": "https://second.invalid"}]
    _, entry, _ = tsamod.request_timestamp(DIGEST, tsas, post=post, anchors=t.anchors)
    assert entry["name"] == "B"


def test_all_tsas_fail():
    def post(url, body):
        raise tsamod.TsaError("weg")
    with pytest.raises(tsamod.TsaError, match="Keine TSA"):
        tsamod.request_timestamp(DIGEST, post=post, anchors=[])


def test_gen_time_reported():
    when = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=1)
    t = TestTSA(gen_time=when)
    _, _, info = tsamod.request_timestamp(DIGEST, post=t.post, anchors=t.anchors)
    assert info.gen_time == when


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl nicht installiert")
def test_openssl_accepts_token(tmp_path):
    data = tmp_path / "data.bin"
    data.write_bytes(b"hallo")
    t = TestTSA()
    der, _, _ = tsamod.request_timestamp(DIGEST, post=t.post, anchors=t.anchors)
    tsr = tmp_path / "x.tsr"
    tsr.write_bytes(der)
    r = subprocess.run(["openssl", "ts", "-verify", "-in", str(tsr), "-data", str(data),
                        "-CAfile", str(FIX / "test-ca.pem")], capture_output=True, text=True)
    assert "Verification: OK" in r.stdout, r.stdout + r.stderr


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl nicht installiert")
def test_accepts_openssl_generated_token(tmp_path):
    """Gegenrichtung: von `openssl ts -reply` erzeugtes Token wird akzeptiert."""
    (tmp_path / "data.bin").write_bytes(b"hallo")
    cnf = tmp_path / "ts.cnf"
    cnf.write_text(f"""[tsa]
default_tsa = t
[t]
serial = {tmp_path / 'serial'}
signer_cert = {FIX / 'test-tsa.pem'}
certs = {FIX / 'test-ca.pem'}
signer_key = {FIX / 'test-tsa.key'}
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.2
digests = sha256
ess_cert_id_alg = sha256
""")
    (tmp_path / "serial").write_text("01\n")
    def run(*a):
        r = subprocess.run(a, capture_output=True, text=True, cwd=tmp_path)
        assert r.returncode == 0, r.stderr
    run("openssl", "ts", "-query", "-data", "data.bin", "-sha256", "-cert", "-out", "q.tsq")
    run("openssl", "ts", "-reply", "-config", str(cnf), "-queryfile", "q.tsq", "-out", "r.tsr")
    info = tsamod.verify_response((tmp_path / "r.tsr").read_bytes(), DIGEST,
                               anchors=TestTSA().anchors)
    assert info.chain_verified


# --- echte Antworten (Fixtures aus scripts/diag_tsa.py, 01.11.2026) ---------

def _real(name):
    from asn1crypto import tsp
    der = (FIX / f"{name}.tsr").read_bytes()
    tst = tsp.TimeStampResp.load(der)["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed
    return der, tst["message_imprint"]["hashed_message"].native


def test_real_digicert_with_cross_signed_root():
    """DigiCert liefert Trusted Root G4 zusätzlich cross-signiert von Assured ID Root CA."""
    der, digest = _real("DigiCert")
    info = tsamod.verify_response(der, digest)
    assert info.chain_verified
    assert "DigiCert Trusted Root G4" in info.anchor_subject


def test_real_freetsa():
    der, digest = _real("FreeTSA")
    info = tsamod.verify_response(der, digest)
    assert info.chain_verified
    assert "freetsa" in info.anchor_subject.lower()


def test_network_error_is_retried_once():
    t = TestTSA()
    calls = []

    def post(url, body):
        calls.append(url)
        if len(calls) == 1:
            raise tsamod.TsaError("DNS-Aussetzer")
        return t.post(url, body)

    _, entry, _ = tsamod.request_timestamp(DIGEST, post=post, anchors=t.anchors, retry_delay=0)
    assert entry["name"] == "FreeTSA" and len(calls) == 2
