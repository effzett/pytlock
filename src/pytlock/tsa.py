"""RFC 3161: Zeitstempel anfordern und Tokens prüfen.

Die Prüfung umfasst: PKIStatus, MessageImprint (SHA-256), Nonce, die
CMS-Signatur über die signierten Attribute, das messageDigest-Attribut,
ESS-signingCertificate(v2), die EKU timeStamping des TSA-Zertifikats und
die Zertifikatskette bis zu einem Vertrauensanker. Dieselben Tokens lassen
sich extern mit `openssl ts -verify` prüfen (siehe docs/FORMAT.md).
"""
from __future__ import annotations

import hashlib
import secrets
import time
import ssl
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from typing import Callable

import certifi
from asn1crypto import algos, cms, core, tsp, x509 as ax509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

DEFAULT_TSAS: list[dict] = [
    {"name": "FreeTSA", "url": "https://freetsa.org/tsr"},
    {"name": "DigiCert", "url": "http://timestamp.digicert.com"},
]


class TsaError(Exception):
    pass


class TsaVerifyError(TsaError):
    pass


@dataclass
class TimestampInfo:
    gen_time: datetime
    serial: int
    policy: str
    tsa_subject: str
    hashed_message: bytes
    chain_verified: bool
    anchor_subject: str | None = None
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Anfrage
# --------------------------------------------------------------------------

def build_request(digest: bytes, nonce: int | None = None) -> tuple[bytes, int]:
    if len(digest) != 32:
        raise ValueError("SHA-256-Digest erwartet")
    if nonce is None:
        nonce = secrets.randbits(63) | 1
    req = tsp.TimeStampReq({
        "version": 1,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "hashed_message": digest,
        }),
        "nonce": nonce,
        "cert_req": True,
    })
    return req.dump(), nonce


PostFn = Callable[[str, bytes], bytes]


def http_post(url: str, body: bytes, timeout: float = 20.0) -> bytes:
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/timestamp-query",
        "Accept": "application/timestamp-reply",
        "User-Agent": "pytlock",
    })
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read()
    except (urllib.error.URLError, OSError) as exc:
        raise TsaError(f"{url}: {exc}") from exc


def request_timestamp(digest: bytes, tsas: list[dict] | None = None,
                      post: PostFn = http_post,
                      anchors: list[x509.Certificate] | None = None,
                      retries: int = 1, retry_delay: float = 1.0
                      ) -> tuple[bytes, dict, TimestampInfo]:
    """Fragt die TSAs der Reihe nach an. Gibt (TSR-DER, TSA-Eintrag, Info) zurück."""
    errors = []
    for tsa in (tsas or DEFAULT_TSAS):
        for attempt in range(retries + 1):
            body, nonce = build_request(digest)
            try:
                der = post(tsa["url"], body)
            except TsaError as exc:  # Netzfehler: kurz warten, erneut versuchen
                if attempt < retries:
                    time.sleep(retry_delay)
                    continue
                errors.append(f"{tsa['name']}: {exc}")
                break
            try:
                info = verify_response(der, digest, nonce=nonce, anchors=anchors)
                return der, tsa, info
            except TsaError as exc:
                errors.append(f"{tsa['name']}: {exc}")
                break
    raise TsaError("Keine TSA lieferte einen gültigen Zeitstempel: " + "; ".join(errors))


# --------------------------------------------------------------------------
# Vertrauensanker
# --------------------------------------------------------------------------

def load_anchors(include_certifi: bool = True) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    pkg = resources.files("pytlock") / "data" / "tsa"
    if pkg.is_dir():
        for entry in sorted(pkg.iterdir(), key=lambda p: p.name):
            if entry.name.endswith((".pem", ".crt")):
                data = entry.read_bytes()
                try:
                    certs.extend(x509.load_pem_x509_certificates(data))
                except ValueError:
                    certs.append(x509.load_der_x509_certificate(data))
    if include_certifi:
        with open(certifi.where(), "rb") as fh, warnings.catch_warnings():
            warnings.simplefilter("ignore")
            certs.extend(x509.load_pem_x509_certificates(fh.read()))
    return certs


# --------------------------------------------------------------------------
# Prüfung
# --------------------------------------------------------------------------

_HASHES = {
    "sha1": hashes.SHA1, "sha224": hashes.SHA224, "sha256": hashes.SHA256,
    "sha384": hashes.SHA384, "sha512": hashes.SHA512,
}


def _hash_cls(name: str):
    try:
        return _HASHES[name]
    except KeyError as exc:
        raise TsaVerifyError(f"Nicht unterstützter Hash: {name}") from exc


def _digest(name: str, data: bytes) -> bytes:
    h = hashes.Hash(_hash_cls(name)())
    h.update(data)
    return h.finalize()


def _attr(signed_attrs, name: str):
    for a in signed_attrs:
        if a["type"].native == name:
            return a["values"][0]
    return None


def _find_signer(signer_info, certs: list[ax509.Certificate]) -> ax509.Certificate:
    sid = signer_info["sid"]
    for c in certs:
        if sid.name == "issuer_and_serial_number":
            if (c.issuer == sid.chosen["issuer"]
                    and c.serial_number == sid.chosen["serial_number"].native):
                return c
        else:
            if c.key_identifier == sid.chosen.native:
                return c
    raise TsaVerifyError("Signaturzertifikat der TSA nicht im Token enthalten")


def _verify_sig(cert: x509.Certificate, sig_algo: str, hash_name: str,
                signature: bytes, data: bytes) -> None:
    pub = cert.public_key()
    h = _hash_cls(hash_name)()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if sig_algo == "rsassa_pss":
                pub.verify(signature, data, padding.PSS(padding.MGF1(h), padding.PSS.AUTO), h)
            else:
                pub.verify(signature, data, padding.PKCS1v15(), h)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, data, ec.ECDSA(h))
        else:
            raise TsaVerifyError("Nicht unterstützter Schlüsseltyp der TSA")
    except InvalidSignature as exc:
        raise TsaVerifyError("CMS-Signatur ungültig") from exc


def _valid_at(cert: x509.Certificate, when: datetime) -> bool:
    return cert.not_valid_before_utc <= when <= cert.not_valid_after_utc


def _spki(cert: x509.Certificate) -> bytes:
    from cryptography.hazmat.primitives.serialization import PublicFormat
    return cert.public_key().public_bytes(serialization_der(), PublicFormat.SubjectPublicKeyInfo)


def _build_chain(leaf: x509.Certificate, pool: list[x509.Certificate],
                 anchors: list[x509.Certificate], when: datetime) -> x509.Certificate | None:
    """Tiefensuche vom TSA-Zertifikat zu einem Vertrauensanker.

    Ein Zertifikat gilt als verankert, wenn ein Anker dasselbe Subject und
    denselben öffentlichen Schlüssel hat. Damit führen auch Cross-Signaturen
    (z. B. DigiCert Trusted Root G4, signiert von Assured ID Root CA) zum Ziel.
    Anker werden bei der Elternsuche vor den Token-Zertifikaten probiert.
    """
    anchor_keys = {(a.subject.public_bytes(), _spki(a)): a for a in anchors}
    candidates = anchors + pool

    def visit(cert: x509.Certificate, depth: int, path: set[bytes]) -> x509.Certificate | None:
        hit = anchor_keys.get((cert.subject.public_bytes(), _spki(cert)))
        if hit is not None:
            return hit
        if depth >= 8:
            return None
        fp = cert.fingerprint(hashes.SHA256())
        if fp in path:
            return None
        path = path | {fp}
        for parent in candidates:
            if parent.subject != cert.issuer or not _valid_at(parent, when):
                continue
            try:
                cert.verify_directly_issued_by(parent)
            except (ValueError, TypeError, InvalidSignature):
                continue
            found = visit(parent, depth + 1, path)
            if found is not None:
                return found
        return None

    return visit(leaf, 0, set())


def serialization_der():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


def parse_response(der: bytes) -> tsp.TimeStampResp:
    try:
        resp = tsp.TimeStampResp.load(der)
        _ = resp.native["status"]
    except Exception as exc:  # noqa: BLE001
        raise TsaVerifyError(f"Antwort ist kein RFC-3161-TimeStampResp: {exc}") from exc
    return resp


def verify_response(der: bytes, digest: bytes, nonce: int | None = None,
                    anchors: list[x509.Certificate] | None = None,
                    require_chain: bool = True) -> TimestampInfo:
    resp = parse_response(der)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        text = resp["status"]["status_string"].native
        raise TsaVerifyError(f"TSA verweigert: {status} {text or ''}".strip())
    token = resp["time_stamp_token"]
    if token["content_type"].native != "signed_data":
        raise TsaVerifyError("Token ist kein CMS SignedData")
    sd = token["content"]
    eci = sd["encap_content_info"]
    if eci["content_type"].native != "tst_info":
        raise TsaVerifyError("Token enthält kein TSTInfo")
    tst_bytes = eci["content"].contents
    tst = eci["content"].parsed

    mi = tst["message_imprint"]
    if mi["hash_algorithm"]["algorithm"].native != "sha256":
        raise TsaVerifyError("TSA hat nicht SHA-256 gestempelt")
    if mi["hashed_message"].native != digest:
        raise TsaVerifyError("Gestempelter Hash passt nicht zu den Daten")
    if nonce is not None and tst["nonce"].native != nonce:
        raise TsaVerifyError("Nonce stimmt nicht überein")

    signer_infos = sd["signer_infos"]
    if len(signer_infos) != 1:
        raise TsaVerifyError("Genau eine Signatur erwartet")
    si = signer_infos[0]
    signed_attrs = si["signed_attrs"]
    if not signed_attrs:
        raise TsaVerifyError("Signierte Attribute fehlen")
    hash_name = si["digest_algorithm"]["algorithm"].native

    ct = _attr(signed_attrs, "content_type")
    if ct is None or ct.native != "tst_info":
        raise TsaVerifyError("content-type-Attribut fehlt oder falsch")
    md = _attr(signed_attrs, "message_digest")
    if md is None or md.native != _digest(hash_name, tst_bytes):
        raise TsaVerifyError("messageDigest passt nicht zum TSTInfo")

    token_certs = [c.chosen for c in (sd["certificates"] or []) if c.name == "certificate"]
    signer_a = _find_signer(si, token_certs)
    signer = x509.load_der_x509_certificate(signer_a.dump())

    # ESS signingCertificate(v2): bindet die Signatur an genau dieses Zertifikat
    cert_der = signer_a.dump()
    sc2 = _attr(signed_attrs, "signing_certificate_v2")
    sc1 = _attr(signed_attrs, "signing_certificate")
    if sc2 is not None:
        first = sc2["certs"][0]
        alg = first["hash_algorithm"]["algorithm"].native if first["hash_algorithm"] else "sha256"
        if first["cert_hash"].native != _digest(alg, cert_der):
            raise TsaVerifyError("signingCertificateV2 passt nicht zum TSA-Zertifikat")
    elif sc1 is not None:
        if sc1["certs"][0]["cert_hash"].native != hashlib.sha1(cert_der).digest():
            raise TsaVerifyError("signingCertificate passt nicht zum TSA-Zertifikat")

    attrs_der = b"\x31" + signed_attrs.dump()[1:]
    sig_algo = si["signature_algorithm"].signature_algo
    _verify_sig(signer, sig_algo, hash_name, si["signature"].native, attrs_der)

    gen_time = tst["gen_time"].native
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)

    warnings: list[str] = []
    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if x509.oid.ExtendedKeyUsageOID.TIME_STAMPING not in eku.value:
            raise TsaVerifyError("TSA-Zertifikat hat keine EKU timeStamping")
        if not eku.critical:
            warnings.append("EKU timeStamping ist nicht als kritisch markiert")
    except x509.ExtensionNotFound as exc:
        raise TsaVerifyError("TSA-Zertifikat hat keine EKU timeStamping") from exc
    if not _valid_at(signer, gen_time):
        raise TsaVerifyError("TSA-Zertifikat war zum Stempelzeitpunkt nicht gültig")

    if anchors is None:
        anchors = load_anchors()
    pool = [x509.load_der_x509_certificate(c.dump()) for c in token_certs]
    anchor = _build_chain(signer, pool, anchors, gen_time)
    if anchor is None:
        if require_chain:
            raise TsaVerifyError("Zertifikatskette der TSA führt zu keinem Vertrauensanker")
        warnings.append("Zertifikatskette nicht verifiziert")

    return TimestampInfo(
        gen_time=gen_time,
        serial=tst["serial_number"].native,
        policy=tst["policy"].dotted,
        tsa_subject=signer.subject.rfc4514_string(),
        hashed_message=digest,
        chain_verified=anchor is not None,
        anchor_subject=anchor.subject.rfc4514_string() if anchor is not None else None,
        warnings=warnings,
    )
