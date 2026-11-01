import os
from datetime import timedelta

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QDateTime  # noqa: E402

from conftest import FakeDrand  # noqa: E402
from pytlock.config import Settings  # noqa: E402
from pytlock.drand import QUICKNET  # noqa: E402
from pytlock.gui.app import MainWindow  # noqa: E402

LATEST = 20_000_000


class TestSettings(Settings):
    __test__ = False

    def __init__(self, tle, tsa, latest):
        super().__init__(post=tsa.post, anchors=tsa.anchors)
        self._tle = tle
        self.latest = latest

    def drand(self):
        return FakeDrand(self.latest)

    def tle(self):
        return self._tle


def test_encrypt_then_decrypt_via_gui(qtbot, tmp_path, fake_tle, tsa):
    st = TestSettings(fake_tle, tsa, LATEST)
    w = MainWindow(st)
    qtbot.addWidget(w)
    src = tmp_path / "notiz.txt"
    src.write_text("Inhalt")
    target = QUICKNET.round_time(LATEST + 50) - timedelta(seconds=1)

    w.enc.src.setText(str(src))
    w.enc.when.setDateTime(QDateTime.fromSecsSinceEpoch(int(target.timestamp())))
    w.enc._suggest_output(force=True)
    out = w.enc.out.text()
    assert out.endswith(".pytlock")
    w.enc.go.click()
    qtbot.waitUntil(lambda: w.enc.worker is None and bool(w.enc.result.toPlainText()), timeout=20000)
    assert "Fertig" in w.enc.result.toPlainText(), w.enc.result.toPlainText()

    # zu früh
    w.dec.src.setText(out)
    w.dec._inspect()
    qtbot.waitUntil(lambda: w.dec.go.isEnabled(), timeout=20000)
    assert "Eingeliefert" in w.dec.details.text()
    w.dec.go.click()
    qtbot.waitUntil(lambda: "Noch gesperrt" in w.dec.result.toPlainText(), timeout=20000)

    # Zielrunde erreicht
    st.latest = LATEST + 60
    fake_tle.set_latest(LATEST + 60)
    w.dec.timer.stop()
    w.dec.outdir.setText(str(tmp_path / "o"))
    (tmp_path / "o").mkdir()
    w.dec.go.click()
    qtbot.waitUntil(lambda: "Entschlüsselt" in w.dec.result.toPlainText(), timeout=20000)
    assert (tmp_path / "o" / "notiz.txt").read_text() == "Inhalt"
