"""Live-Tests gegen das echte drand-Netz, echte TSAs und das echte tle-Binary.

Aufruf:  pytest -m live
Voraussetzung: Netz, tle im PATH oder PYTLOCK_TLE gesetzt.
"""
import shutil
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone

import certifi
import pytest

from pytlock import core, tsa
from pytlock.config import Settings
from pytlock.drand import QUICKNET

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def st():
    return Settings.load()


def test_drand_chain_matches_pin(st):
    d = st.drand()
    assert d.verify_chain() is QUICKNET
    latest = d.latest_round()
    # Plausibilität: Rundennummer passt zur Wanduhr (±1 h)
    assert abs(QUICKNET.round_at(datetime.now(timezone.utc)) - latest) < 1200


def test_roundtrip_against_past_round(tmp_path, st):
    d = st.drand()
    d.verify_chain()
    target = QUICKNET.round_time(d.latest_round() - 3)
    src = tmp_path / "live.txt"
    src.write_bytes(b"pytlock live test\n" * 1000)
    dst = tmp_path / "live.pytlock"
    res = core.encrypt_file(src, dst, target, drand=d, tle=st.tle(), tsas=st.tsas,
                            allow_past=True)
    assert all(s.info.chain_verified for s in res.stamps)
    out = tmp_path / "o"
    out.mkdir()
    r = core.decrypt_file(dst, out, drand=st.drand(), tle=st.tle())
    assert r.output.read_bytes() == src.read_bytes()

    # Interoperabilität: payload.age mit dem nackten tle entschlüsseln
    with zipfile.ZipFile(dst) as zf:
        zf.extractall(tmp_path / "x")
    tle_cmd = st.tle().command
    p = subprocess.run(tle_cmd + ["-d", "-o", str(tmp_path / "raw.txt"),
                                  str(tmp_path / "x" / core.PAYLOAD)], capture_output=True)
    assert p.returncode == 0, p.stderr
    assert (tmp_path / "raw.txt").read_bytes() == src.read_bytes()

    # externe Prüfung des Zeitstempels mit openssl
    if shutil.which("openssl"):
        cafile = tmp_path / "anchors.pem"
        from cryptography.hazmat.primitives.serialization import Encoding
        cafile.write_bytes(b"".join(c.public_bytes(Encoding.PEM) for c in tsa.load_anchors()))
        v = subprocess.run(["openssl", "ts", "-verify", "-in", str(tmp_path / "x" / core.PAYLOAD_TSR),
                            "-data", str(tmp_path / "x" / core.PAYLOAD), "-CAfile", str(cafile)],
                           capture_output=True, text=True)
        assert "Verification: OK" in v.stdout, v.stdout + v.stderr


def test_future_round_is_locked(tmp_path, st):
    src = tmp_path / "f.txt"
    src.write_bytes(b"zukunft")
    dst = tmp_path / "f.pytlock"
    core.encrypt_file(src, dst, datetime.now(timezone.utc) + timedelta(hours=1),
                      drand=st.drand(), tle=st.tle(), tsas=st.tsas)
    with pytest.raises(core.NotYet) as ei:
        core.decrypt_file(dst, tmp_path, drand=st.drand(), tle=st.tle())
    assert 3000 < ei.value.remaining_seconds <= 3610


def test_tle_itself_refuses_early(tmp_path, st):
    """Ohne pytlock-Vorprüfung: tle selbst liefert vor der Runde nichts."""
    d = st.drand()
    tle = st.tle()
    ct = tle.encrypt_bytes(b"x", d.latest_round() + 1000)
    from pytlock.tle import TooEarly
    with pytest.raises(TooEarly):
        tle.decrypt_bytes(ct)
