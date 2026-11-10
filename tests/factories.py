"""Row factories for the test suite.

``DataEncryptionKey`` references its ``KeyEncryptionKey`` by foreign key, so a
data key cannot be created without one. These helpers keep that from turning
every test into two-step setup, and keep the tests honest about the relation
rather than letting them invent rows with no KEK behind them.
"""

from __future__ import annotations

from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey


def make_kek(kek_resource_name="kek-1", key_store="local", **fields):
    """Get or create the KEK row named by *kek_resource_name*.

    Get-or-create rather than create: several data keys in one test commonly
    share a key encryption key, which is the case worth exercising — a shared
    KEK is exactly what the deletion gates must refuse to destroy.
    """
    row, _created = KeyEncryptionKey.objects.get_or_create(
        key_store=key_store,
        kek_resource_name=kek_resource_name,
        defaults=fields,
    )
    return row


def make_dek(
    silo_uid="team-1",
    *,
    purpose=DataEncryptionKey.PURPOSE_FIELD,
    kek_resource_name="kek-1",
    key_store="local",
    kek=None,
    **fields,
):
    """Create a data encryption key row, making its KEK row if needed."""
    fields.setdefault("silo_label", "team")
    fields.setdefault("encrypted_keyset", b"wrapped")
    fields.setdefault("crypto_backend", "pyca-cryptography")
    return DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=silo_uid,
        purpose=purpose,
        kek=kek or make_kek(kek_resource_name, key_store),
        **fields,
    )


def make_kek_row(**fields):
    """Get or create a KEK row from arbitrary field values.

    Stands in for ``KeyEncryptionKey.objects.create`` in tests that also build
    data keys: those create their KEK through :func:`make_kek`, so a second
    create with the same identity would violate the uniqueness constraint. The
    identity is ``(key_store, kek_resource_name)``; everything else is a
    default applied on creation.
    """
    identity = {
        "key_store": fields.pop("key_store", "local"),
        "kek_resource_name": fields.pop("kek_resource_name", "kek-1"),
    }
    row, created = KeyEncryptionKey.objects.get_or_create(**identity, defaults=fields)
    if created or not fields:
        return row
    # A data key built earlier in the test may already have created this row, and
    # the caller's fields are the point of calling this — so apply them. Identity
    # columns are excluded: the model refuses to have them reassigned, which is
    # the guarantee that a row never silently comes to stand for a different key.
    mutable = {name: value for name, value in fields.items() if name not in KeyEncryptionKey.IDENTITY_FIELDS}
    for name, value in mutable.items():
        setattr(row, name, value)
    if mutable:
        row.save(update_fields=[*mutable, "updated_at"])
    return row


def make_user(username="alice", **fields):
    """Get or create a user the ledger can point at.

    The ledger records who acted as a reference to ``AUTH_USER_MODEL``, so a test
    that asserts on attribution needs a real row rather than a name.
    """
    from django.contrib.auth import get_user_model

    row, _created = get_user_model().objects.get_or_create(username=username, defaults=fields)
    return row
