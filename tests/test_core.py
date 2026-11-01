import hashlib
import json
import os
import threading
import zipfile
from datetime import timedelta

import pytest

from conftest import FakeDrand
from pytlock import core
from pytlock.drand import QUICKNET
from pytlock.tle import Cancelled

LATEST = 20_000_000


def _target(rounds_ahead: int = 100):
    return QUICKNET.round_time(LATEST + rounds_ahead) - timedelta(seconds=1)


def _encrypt(tmp_path, fake_tle, tsa, data=b"geheim\n", name="brief.txt", **kw):
    src = tmp_path / name
    src.write_bytes(data)
    dst = tmp_path / "out.pytlock"
    res = core.encrypt_file(src, dst, _target(), drand=FakeDrand(LATEST), tle=fake_tle,
                            post=tsa.post, anchors=tsa.anchors, **kw)
    return src, dst, res


def test_roundtrip(tmp_path, fake_tle, tsa):
    src, dst, res = _encrypt(tmp_path, fake_tle, tsa)
    assert res.round == LATEST + 100
    out = tmp_path / "out"
    out.mkdir()
    fake_tle.set_latest(LATEST + 100)
    r = core.decrypt_file(dst, out, drand=FakeDrand(LATEST + 100), tle=fake_tle,
                          anchors=tsa.anchors)
    assert r.output.read_bytes() == src.read_bytes()
    assert r.original_name == "brief.txt"
    assert not list(out.glob("*.part"))


def test_container_layout_and_metadata(tmp_path, fake_tle, tsa):
    src, dst, res = _encrypt(tmp_path, fake_tle, tsa)
    with zipfile.ZipFile(dst) as zf:
        names = set(zf.namelist())
        meta = json.loads(zf.read(core.META))
        assert all(i.compress_type == zipfile.ZIP_STORED for i in zf.infolist())
    assert names == {core.META, core.PAYLOAD, core.SECRET, core.PAYLOAD_TSR,
                     core.COMMIT_TSR, core.README}
    assert meta["version"] == 1
    assert meta["drand"]["round"] == res.round
    assert meta["drand"]["chain_hash"] == QUICKNET.chain_hash
    assert {t["covers"] for t in meta["timestamps"]} == {"payload", "commitment"}


def test_plaintext_hash_not_exposed(tmp_path, fake_tle, tsa):
    """Erratbare Inhalte dürfen nicht über einen offenen Klartext-Hash prüfbar sein."""
    data = b"ja"
    _, dst, _ = _encrypt(tmp_path, fake_tle, tsa, data=data, name="antwort.txt")
    plain_hash = hashlib.sha256(data).hexdigest()
    with zipfile.ZipFile(dst) as zf:
        for n in (core.META, core.README):
            text = zf.read(n).decode()
            assert plain_hash not in text
            assert "antwort.txt" not in text


def test_too_early(tmp_path, fake_tle, tsa):
    _, dst, res = _encrypt(tmp_path, fake_tle, tsa)
    with pytest.raises(core.NotYet) as ei:
        core.decrypt_file(dst, tmp_path, drand=FakeDrand(LATEST + 10), tle=fake_tle,
                          anchors=tsa.anchors)
    assert ei.value.remaining_seconds == 90 * 3
    assert ei.value.target_round == res.round


def test_too_early_even_if_relay_lies_tle_refuses(tmp_path, fake_tle, tsa):
    """Auch wenn die Vorprüfung getäuscht wird, liefert tle vorher nichts."""
    _, dst, res = _encrypt(tmp_path, fake_tle, tsa)
    fake_tle.set_latest(LATEST)  # "echtes" Netz ist noch nicht so weit
    with pytest.raises(core.NotYet):
        core.decrypt_file(dst, tmp_path, drand=_LyingThenHonest(res.round, LATEST),
                          tle=fake_tle, anchors=tsa.anchors)


class _LyingThenHonest(FakeDrand):
    def __init__(self, lie, truth):
        super().__init__(truth)
        self.calls = 0
        self.lie = lie

    def latest_round(self):
        self.calls += 1
        return self.lie if self.calls == 1 else self.latest


def test_target_in_past_rejected(tmp_path, fake_tle, tsa):
    src = tmp_path / "a.txt"
    src.write_bytes(b"x")
    with pytest.raises(core.TargetInPast):
        core.encrypt_file(src, tmp_path / "o.pytlock", QUICKNET.round_time(LATEST - 5),
                          drand=FakeDrand(LATEST), tle=fake_tle, post=tsa.post,
                          anchors=tsa.anchors)
    assert not list(tmp_path.glob("*.pytlock*"))


def test_tampered_payload_detected(tmp_path, fake_tle, tsa):
    _, dst, res = _encrypt(tmp_path, fake_tle, tsa, data=b"A" * 5000)
    tampered = tmp_path / "t.pytlock"
    with zipfile.ZipFile(dst) as zin, zipfile.ZipFile(tampered, "w") as zout:
        for n in zin.namelist():
            b = zin.read(n)
            if n == core.PAYLOAD:
                b = b[:-1] + bytes([b[-1] ^ 1])
            zout.writestr(n, b)
    info = core.inspect(tampered, anchors=tsa.anchors)
    assert info.payload_hash_ok is False
    out = tmp_path / "o"
    out.mkdir()
    fake_tle.set_latest(res.round)
    with pytest.raises(core.IntegrityError):
        core.decrypt_file(tampered, out, drand=FakeDrand(res.round), tle=fake_tle,
                          anchors=tsa.anchors)
    assert list(out.iterdir()) == []


def test_inspect_reports_submission_time(tmp_path, fake_tle, tsa):
    _, dst, _ = _encrypt(tmp_path, fake_tle, tsa)
    info = core.inspect(dst, anchors=tsa.anchors)
    assert info.payload_hash_ok is True
    assert len(info.stamps) == 2 and not info.stamp_errors
    assert all(s.info.chain_verified for s in info.stamps)
    assert info.submission_time is not None


def test_cancel_removes_partial(tmp_path, fake_tle, tsa):
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(3 * 1024 * 1024))
    ev = threading.Event()

    def progress(phase, done, total):
        if phase == "encrypt" and done >= 1024 * 1024:
            ev.set()

    with pytest.raises(Cancelled):
        core.encrypt_file(src, tmp_path / "o.pytlock", _target(), drand=FakeDrand(LATEST),
                          tle=fake_tle, post=tsa.post, anchors=tsa.anchors,
                          progress=progress, cancel=ev)
    assert not list(tmp_path.glob("o.pytlock*"))


def test_large_file_streaming(tmp_path, fake_tle, tsa):
    data = os.urandom(12 * 1024 * 1024 + 17)
    _, dst, res = _encrypt(tmp_path, fake_tle, tsa, data=data, name="gross.bin")
    out = tmp_path / "o"
    out.mkdir()
    fake_tle.set_latest(res.round)
    r = core.decrypt_file(dst, out, drand=FakeDrand(res.round), tle=fake_tle,
                          anchors=tsa.anchors)
    assert r.size == len(data)
    assert hashlib.sha256(r.output.read_bytes()).digest() == hashlib.sha256(data).digest()


def test_no_overwrite_on_decrypt(tmp_path, fake_tle, tsa):
    _, dst, res = _encrypt(tmp_path, fake_tle, tsa)
    out = tmp_path / "o"
    out.mkdir()
    (out / "brief.txt").write_text("schon da")
    fake_tle.set_latest(res.round)
    r = core.decrypt_file(dst, out, drand=FakeDrand(res.round), tle=fake_tle,
                          anchors=tsa.anchors)
    assert r.output.name == "brief (1).txt"
    assert (out / "brief.txt").read_text() == "schon da"


@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd", "passwd"),
    ("C:\\Windows\\x.dll", "x.dll"),
    ("", "entschluesselt.bin"),
    ("a:b?.txt", "a_b_.txt"),
])
def test_safe_filename(raw, expected):
    assert core.safe_filename(raw) == expected


def test_rejects_non_container(tmp_path):
    p = tmp_path / "x.pytlock"
    p.write_bytes(b"kein zip")
    with pytest.raises(core.FormatError):
        core.inspect(p)
