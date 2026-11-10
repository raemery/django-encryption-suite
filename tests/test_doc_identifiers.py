"""Drift guard: every package identifier the docs name must actually exist.

A guard already exists for a signal that silently rotted once —
``test_error_codes.py`` freezes the error slugs. Documentation referring to
*code* had no such guard, and drifted
the same way: a bullet listed ``ByokKekStrategy`` beside real strategy classes
though it only ever existed as a worked example a reader writes; a getting-started
page named an env var no package code reads; ``logging.md`` quoted a log
message that had been reworded out of existence. All three read as authoritative
and all three were wrong.

This checks the cheap, mechanical half of that problem: a backticked
``CONSTANT_CASE`` or ``ClassName`` token in ``docs/`` must appear somewhere in
``src/``, or be an acknowledged external name.

It cannot check prose accuracy — a doc can describe a real symbol's behavior
incorrectly and still pass. It catches the reference that names something which
is not there at all.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SRC = ROOT / "src" / "encryption_suite"

# The changelog is a record of what shipped, written once at release and not
# maintained afterwards, so it names identifiers that were real when the entry
# was written and have since been renamed or retired. Holding it to the current
# source would force a rewrite of released history on every rename.
UNMAINTAINED = {"changelog.md"}


def _current_docs():
    return [doc for doc in sorted(DOCS.glob("*.md")) if doc.name not in UNMAINTAINED]


# Identifiers that belong to something other than this package. Grouped by owner
# so an addition has to state what it is — an unexplained entry here is how a
# guard turns into a rubber stamp.
EXTERNAL = {
    # --- Django settings, classes, and management concepts ------------------
    "DJANGO_SETTINGS_MODULE",
    "FORM_RENDERER",
    "LANGUAGE_CODE",
    "LOCALE_PATHS",
    "LocaleMiddleware",
    "AlterField",
    "SECRET_KEY",
    # Django's streaming response base, named where the admin docs explain a log
    # line Django emits for its own static files. (FileResponse is not listed:
    # the package uses it, so it stays checked.)
    "StreamingHttpResponse",
    # --- django-tenants (an optional integration, not a dependency) ---------
    "SHARED_APPS",
    "TENANT_APPS",
    "MULTITENANT_RELATIVE_MEDIA_ROOT",
    "TenantFileSystemStorage",
    "TenantMainMiddleware",
    # --- django-allauth (an optional integration, not a dependency) ---------
    # Named by working-with-django-allauth.md: the setting that decides whether
    # its token columns are written, and the setting its username generator reads.
    "SOCIALACCOUNT_STORE_TOKENS",
    "USER_MODEL_USERNAME_FIELD",
    # Its two admin classes, named where the page says both need their searches
    # re-registered with exact matches.
    "EmailAddressAdmin",
    "SocialAccountAdmin",
    # --- SaaS Pegasus, the host project in the examples ---------------------
    "TeamsMiddleware",
    # --- Python standard library --------------------------------------------
    "FileNotFoundError",
    "ThreadPoolExecutor",
    "DELETE_ON_CLOSE",
    "FILE_ATTRIBUTE_TEMPORARY",
    # --- django-storages / boto3 --------------------------------------------
    "S3Boto3StorageFile",
    # --- Provider API operations and error codes ----------------------------
    "AccessDenied",
    "CreateCryptoKey",
    "CredentialUnavailableError",
    "GenerateDataKey",
    "InvalidIdentityToken",
    "KMS_DECRYPT",
    "KMS_ENCRYPT",
    "KeyCreate",
    "KeyDisabled",
    "KeyNotEnabled",
    "StringEquals",
    "StringLike",
    # AWS KMS's default CreateKey Origin, named where kek-provisioning.md says the
    # provisioner sends Origin only with a custom key store.
    "AWS_KMS",
    # --- Environment variables read by an SDK or the host, never by us ------
    "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "SPIFFE_ENDPOINT_SOCKET",
    "ASGI_THREADS",
    # --- Worked examples the reader writes, which the package does not ship --
    # Named here rather than removed from the docs: the example is the point,
    # and `kek-provisioning.md` now says explicitly that it is not shipped.
    "ByokKekStrategy",
    # The reader's own user model in the user-column examples: the project's,
    # not the package's.
    "CustomUser",
    # The storage class the key set example in `concepts.md` composes from
    # `SiloEncryptedStorageMixin` and a storage backend: the reader's own.
    "EncryptedRestrictedStorage",
    # The same, in the storage composition example in `managing-encrypted-files.md`.
    "EncryptedArchiveStorage",
    # Environment variables the GCP settings example reads with env(): the
    # reader's own names, which the package never reads.
    "GCP_WIF_POOL_ID",
    "GCP_WIF_PROVIDER_ID",
}

_TOKEN = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)`")


def _source_text() -> str:
    """Every hand-written source file in the package, as one string.

    Migrations are excluded: they are generated, and the Django operation names
    in them (``AlterField``, ``AddField``) are framework symbols, not the
    package's. Counting them would let a migration silently satisfy a docs
    reference to a name this package does not define.
    """
    parts = [p.read_text(encoding="utf-8") for p in SRC.rglob("*.py") if "migrations" not in p.parts]
    parts += [p.read_text(encoding="utf-8") for p in SRC.rglob("*.html")]
    return "\n".join(parts)


def _is_defined_in(source: str, name: str) -> bool:
    """Whether *source* defines *name*, as a class, function or assignment.

    Stricter than asking whether the name appears, which is all the reference
    check above needs: a settings key the package only ever reads by string
    appears and is never defined, and counts as ours either way. Shadowing is
    the opposite question — whether the package owns the name — and mere
    appearance answers it wrongly twice over. ``Authenticator`` is
    django-allauth's model, and the package names it in a docstring while
    defining nothing of the sort; it would also read as present through any
    longer name that contains it.
    """
    pattern = (
        rf"^[ \t]*(?:async[ \t]+)?(?:class|def)[ \t]+{re.escape(name)}\b|^[ \t]*{re.escape(name)}[ \t]*(?::[^=\n]+)?="
    )
    return re.search(pattern, source, re.MULTILINE) is not None


def _looks_like_an_identifier(head: str) -> bool:
    """Whether a backticked token is shaped like a symbol rather than prose.

    Deliberately narrow: ``CONSTANT_CASE`` (all caps with an underscore) and
    ``ClassName`` (leading capital, not all caps). Lowercase tokens are excluded
    — ``field``, ``active``, ``deleted`` are ordinary words in backticks far more
    often than they are symbols, and flagging them would drown the signal.
    """
    return (head.isupper() and "_" in head) or (head[:1].isupper() and not head.isupper())


def test_documented_identifiers_exist_in_the_package():
    source = _source_text()
    unknown: dict[str, set[str]] = {}
    for doc in _current_docs():
        for token in _TOKEN.findall(doc.read_text(encoding="utf-8")):
            head = token.split(".")[0]
            if not _looks_like_an_identifier(head) or head in EXTERNAL or head in source:
                continue
            unknown.setdefault(head, set()).add(doc.name)

    assert not unknown, (
        "docs name identifiers that do not exist in src/encryption_suite: "
        + "; ".join(f"{name} ({', '.join(sorted(docs))})" for name, docs in sorted(unknown.items()))
        + ". Fix the reference, or add the name to EXTERNAL with a comment saying whose it is."
    )


def test_external_allowlist_has_no_dead_entries():
    """An allowlist entry for a name no doc mentions is stale.

    Without this the list only ever grows, and a future reader cannot tell which
    entries still earn their place.
    """
    mentioned = set()
    for doc in _current_docs():
        for token in _TOKEN.findall(doc.read_text(encoding="utf-8")):
            mentioned.add(token.split(".")[0])

    dead = sorted(EXTERNAL - mentioned)
    assert not dead, f"EXTERNAL lists names no doc mentions any more: {dead}. Remove them."


def test_external_allowlist_does_not_shadow_real_symbols():
    """A name that exists in the package must not sit on the external list.

    Otherwise a genuine symbol could be renamed out of existence while the docs
    keep naming it, and the allowlist would quietly absorb the drift.
    """
    source = _source_text()
    shadowed = sorted(name for name in EXTERNAL if _is_defined_in(source, name))
    assert not shadowed, (
        f"EXTERNAL lists names that do exist in the package: {shadowed}. "
        "Remove them from the allowlist so they are checked."
    )
