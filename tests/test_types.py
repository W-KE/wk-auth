"""Column type invariants.

These look pedantic. They exist because getting one of them wrong produces
a query that returns nothing rather than an error — the worst kind of bug
to find, and the exact one this package exists to stop from recurring
across every app that uses it.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi_users_db_sqlalchemy.generics import GUID as FastAPIUsersGUID

from wk_auth import GUID, UTCDateTime


class _Dialect:
    def __init__(self, name: str):
        self.name = name

    def type_descriptor(self, value):
        return value


@pytest.mark.parametrize("dialect", ["sqlite", "postgresql"])
def test_guid_matches_the_format_fastapi_users_stores(dialect: str):
    value = uuid.uuid4()
    ours = GUID().process_bind_param(value, _Dialect(dialect))
    theirs = FastAPIUsersGUID().process_bind_param(value, _Dialect(dialect))
    assert ours == theirs


def test_guid_round_trips():
    value = uuid.uuid4()
    dialect = _Dialect("sqlite")
    stored = GUID().process_bind_param(value, dialect)
    assert GUID().process_result_value(stored, dialect) == value


def test_utc_datetime_reattaches_the_zone_sqlite_drops():
    dialect = _Dialect("sqlite")
    naive = datetime(2026, 3, 1, 9, 15)
    restored = UTCDateTime().process_result_value(naive, dialect)
    assert restored.tzinfo is timezone.utc


def test_utc_datetime_normalises_other_zones_on_write():
    dialect = _Dialect("sqlite")
    nzdt = timezone(timedelta(hours=13))
    aware = datetime(2026, 3, 1, 9, 15, tzinfo=nzdt)
    bound = UTCDateTime().process_bind_param(aware, dialect)
    assert bound.utcoffset() == timedelta(0)
    assert (bound.hour, bound.day) == (20, 28)
