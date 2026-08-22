"""Column types shared by every app that uses this package."""
from __future__ import annotations

import uuid
from datetime import timezone

from sqlalchemy import DateTime
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.types import CHAR, TypeDecorator


class GUID(TypeDecorator):
    """Platform-independent UUID column: native on Postgres, CHAR(36) on SQLite.

    The stored form on SQLite is the dashed string, **not** ``uuid.hex``.
    That is not a style choice: fastapi-users' own GUID type (used for
    ``user.id`` and the access-token table) stores the dashed form, and any
    column that is a foreign key to ``user.id`` has to compare equal to it
    in SQL. With 32-char hex on one side and 36-char dashed on the other, a
    join between the two tables silently returns no rows — equality still
    works wherever both sides are bound through the same type, so nothing
    fails until a query actually joins them.

    ``tests/test_types.py`` asserts the two formats agree.
    """

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID())
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return str(uuid.UUID(str(value)))

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return value if isinstance(value, uuid.UUID) else uuid.UUID(value)


class UTCDateTime(TypeDecorator):
    """A timezone-aware DateTime that survives SQLite.

    SQLite has no native timestamp type: SQLAlchemy stores datetimes as
    strings and hands them back *naive*, dropping the offset. Pydantic then
    serialises them without a ``Z``/``+00:00``, and the browser's
    ``new Date()`` reads them as local time — silently shifting every
    timestamp by the viewer's UTC offset.

    So: normalise to UTC on the way in, re-attach UTC on the way out.
    """

    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(DateTime(timezone=True))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            # Everything written through this type — and SQLite's own
            # CURRENT_TIMESTAMP server defaults — is UTC.
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
