from datetime import datetime, timedelta, timezone

import pytest

from pytlock.drand import ChainMismatch, DrandClient, QUICKNET


def test_round_time_genesis():
    assert QUICKNET.round_time(1) == datetime.fromtimestamp(QUICKNET.genesis_time, timezone.utc)
    assert QUICKNET.round_time(2) - QUICKNET.round_time(1) == timedelta(seconds=3)


def test_round_at_is_first_round_not_before_target():
    t = datetime(2027, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    r = QUICKNET.round_at(t)
    assert QUICKNET.round_time(r) >= t
    assert QUICKNET.round_time(r - 1) < t


def test_round_at_exact_boundary():
    t = QUICKNET.round_time(1000)
    assert QUICKNET.round_at(t) == 1000
    assert QUICKNET.round_at(t + timedelta(milliseconds=1)) == 1001


def test_round_at_requires_tz():
    with pytest.raises(ValueError):
        QUICKNET.round_at(datetime(2027, 1, 1))


def test_verify_chain_rejects_other_key(monkeypatch):
    c = DrandClient()
    info = {"public_key": "00", "period": 3, "genesis_time": QUICKNET.genesis_time,
            "hash": QUICKNET.chain_hash, "schemeID": QUICKNET.scheme}
    monkeypatch.setattr(c, "_get_json", lambda path: info)
    with pytest.raises(ChainMismatch):
        c.verify_chain()


def test_verify_chain_accepts_pinned(monkeypatch):
    c = DrandClient()
    info = {"public_key": QUICKNET.public_key, "period": 3,
            "genesis_time": QUICKNET.genesis_time, "hash": QUICKNET.chain_hash,
            "schemeID": QUICKNET.scheme, "metadata": {"beaconID": "quicknet"}}
    monkeypatch.setattr(c, "_get_json", lambda path: info)
    assert c.verify_chain() is QUICKNET
