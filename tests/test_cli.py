from datetime import datetime, timedelta, timezone

from pytlock import strings as S
from pytlock.cli import parse_when


def test_parse_iso_with_zone():
    assert parse_when("2027-01-01T12:00Z") == datetime(2027, 1, 1, 12, tzinfo=timezone.utc)


def test_parse_iso_local_gets_zone():
    assert parse_when("2027-01-01T12:00").tzinfo is not None


def test_parse_duration():
    d = parse_when("2h") - datetime.now(timezone.utc)
    assert timedelta(hours=1, minutes=59) < d <= timedelta(hours=2)


def test_fmt_duration():
    assert S.fmt_duration(90061) == "1 Tag 1 Std. 1 Min. 1 Sek."
    assert S.fmt_duration(59) == "59 Sek."
