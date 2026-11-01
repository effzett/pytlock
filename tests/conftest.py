import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pytlock.drand import QUICKNET  # noqa: E402
from pytlock.tle import Tle  # noqa: E402
from testtsa import TestTSA  # noqa: E402


class FakeDrand:
    def __init__(self, latest: int):
        self.latest = latest
        self.chain = QUICKNET
        self.active_relay = "https://relay.invalid/"

    def verify_chain(self):
        return QUICKNET

    def latest_round(self):
        return self.latest


@pytest.fixture
def fake_tle(monkeypatch):
    def set_latest(n: int):
        monkeypatch.setenv("FAKE_TLE_LATEST", str(n))
    set_latest(0)
    tle = Tle(command=[sys.executable, str(Path(__file__).parent / "fake_tle.py")])
    tle.set_latest = set_latest
    return tle


@pytest.fixture
def tsa():
    return TestTSA()
