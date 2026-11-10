"""Django REST Framework integration for django-encryption-suite.

Opt-in (requires the ``[drf]`` extra). Keeps the core package
presentation-neutral: this module is the DRF *adapter* that consumes the core's
structured signals and renders them into DRF responses. Three pieces:

* :func:`api_exception_handler` — set as
  ``REST_FRAMEWORK["EXCEPTION_HANDLER"]`` (DRF-only; it runs for exceptions
  raised inside DRF views, never plain Django views) so a ``EncryptionError``
  (e.g. an encrypt failure on a write) returns ``{"code": <slug>, "detail": <message>}``
  with a status that tells the client whether to retry, instead of an unhandled
  ``500``. ``code`` is the stable, language-neutral slug for machines;
  ``detail`` is the generic, translated, user-safe message; operator detail
  stays in the logs.

* :class:`EncryptionSerializerMixin` — mix into a serializer so an
  *undecryptable* field on read is represented as ``null`` plus a
  ``encryption_suite_errors`` map, instead of the stringified fallback sentinel. A
  human UI can render that sentinel string, but a machine API consumer cannot
  distinguish it from real plaintext — so over an API the failure must be a
  structured, type-stable signal. The same mixin answers for writes: a field
  whose plaintext is held unique over a blind index gets the uniqueness check
  ``ModelSerializer`` builds from ``field.unique``, which an encrypted field
  cannot report — see :class:`BlindIndexUniqueValidator`.

* :class:`IgnoreClientContentNegotiation` — set as ``content_negotiation_class``
  on an action that streams a decrypted file, so a client asking for the file's
  own media type is not refused with a ``406`` before the file is opened.
"""

from __future__ import annotations

try:
    from rest_framework import status
    from rest_framework.exceptions import ValidationError as DrfValidationError
    from rest_framework.negotiation import BaseContentNegotiation
    from rest_framework.response import Response
    from rest_framework.validators import UniqueValidator
    from rest_framework.views import exception_handler as drf_exception_handler
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "encryption_suite.contrib.drf requires Django REST Framework. "
        "Install the optional extra: pip install 'django-encryption-suite[drf]'."
    ) from exc

from ..exceptions import (
    DekDeletedError,
    DekDeletionScheduledError,
    DekReencryptionInProgressError,
    EncryptionError,
    KekNotProvisionedError,
    KekUnavailableError,
    MissingDekError,
)

# The status answers one question for the client: is a retry worth making?
# `code` carries everything finer-grained, so only distinctions a generic HTTP
# layer can act on earn a status of their own.
#
# 502 — an upstream failed, and we cannot tell whether it will recover. A
# capped client-side backoff is the right posture; the length of that budget is
# the client's call, so no Retry-After is sent. This is the only entry a client
# should retry.
#
# 409 — a key state that clears only when a person acts: provisioning a key
# encryption key, canceling a deletion, finishing or rolling back a data key
# rotation. All of them can persist for days, none of them can be estimated,
# and a rotation's fence is human time rather than machine time. Announcing any
# of these as temporary invites a retry loop that adds load without ever
# succeeding — the same reason a user-facing message may not say "currently"
# (see the error-message rules in exceptions.py).
#
# Everything else — configuration errors, operation failures, and any subclass
# nobody has classified — falls through to 500. An unmapped error is by
# definition one nobody has reasoned about, so the safe reading is that the
# fault is ours, and none of these arrive on a request that failed to parse or
# validate.
#
# Operators are not served by this map at all. They read the ERROR line and its
# slug (docs/error-codes.md); inflating a status to reach a 5xx alert filter
# would spend client retry pressure on a notification channel that already
# exists.
_HTTP_STATUS = {
    KekUnavailableError: status.HTTP_502_BAD_GATEWAY,
    MissingDekError: status.HTTP_409_CONFLICT,
    KekNotProvisionedError: status.HTTP_409_CONFLICT,
    DekDeletionScheduledError: status.HTTP_409_CONFLICT,
    DekDeletedError: status.HTTP_409_CONFLICT,
    DekReencryptionInProgressError: status.HTTP_409_CONFLICT,
}


def _status_for(exc: EncryptionError) -> int:
    """The mapped status for *exc*, inherited from the nearest mapped ancestor.

    Walking the MRO rather than looking up ``type(exc)`` is what makes a
    subclass follow its parent: ``KekPendingDeletionError`` subclasses
    ``KekNotProvisionedError`` and needs no entry of its own, and a subclass a
    consuming project adds later lands on its parent's status instead of the
    default. Most-derived first, so an entry of its own still wins.
    """
    for cls in type(exc).__mro__:
        mapped = _HTTP_STATUS.get(cls)
        if mapped is not None:
            return mapped
    return status.HTTP_500_INTERNAL_SERVER_ERROR


def api_exception_handler(exc, context):
    """DRF ``EXCEPTION_HANDLER`` that renders a ``EncryptionError`` as JSON.

    DRF-specific: DRF invokes this only for exceptions raised inside its own
    views (``APIView`` / ``ViewSet``); it does not affect plain Django views.

    Returns ``{"code": exc.code, "detail": str(exc)}`` with a mapped status for
    any ``EncryptionError`` (the write path: an encrypt failure raises and
    propagates here). All other exceptions fall through to DRF's default
    handler. A ``EncryptionError`` is a ``ValueError`` subclass, which DRF's
    default handler does not convert, so without this it would surface as an
    unhandled 500 with no body a client can read; an unclassified one still
    answers 500, but with the slug and the generic message attached.
    """
    if isinstance(exc, EncryptionError):
        return Response({"code": exc.code, "detail": str(exc)}, status=_status_for(exc))
    return drf_exception_handler(exc, context)


class IgnoreClientContentNegotiation(BaseContentNegotiation):
    """Content negotiation for an action that streams a decrypted file.

    DRF negotiates before the action runs, so a client sending
    ``Accept: application/octet-stream`` or ``image/jpeg`` is refused with a
    ``406`` before ``serve_encrypted_file`` opens anything — no renderer
    produces those types, and a ``FileResponse`` never passes through a renderer
    anyway. This skips the ``Accept`` check and picks the view's first renderer,
    which only renders what DRF renders itself: an error from
    :func:`api_exception_handler`, so a failed download still answers
    ``{"code", "detail"}``. Set it on the action, not the viewset, so the
    viewset's other actions keep honoring ``Accept``::

        @action(detail=True, methods=["get"], content_negotiation_class=IgnoreClientContentNegotiation)
        def download(self, request, *args, **kwargs):
            return serve_encrypted_file(request, self.get_object(), "file")

    The pattern is the one DRF documents under "Custom content negotiation".
    """

    def select_parser(self, request, parsers):
        return parsers[0]

    def select_renderer(self, request, renderers, format_suffix=None):
        return renderers[0], renderers[0].media_type


def _holds_unique_blind_index(model_field) -> bool:
    """Whether *model_field*'s plaintext is held unique over a blind index."""
    from ..fields import _CiphertextFieldMixin

    return isinstance(model_field, _CiphertextFieldMixin) and model_field.blind_index and model_field.index_unique


class BlindIndexUniqueValidator:
    """The uniqueness check DRF would have built, run against the digest.

    ``ModelSerializer`` attaches a ``UniqueValidator`` to a field whose model
    field reports ``unique``, and an encrypted field reports ``False`` — it has
    to, or the database would be asked for a unique index over ciphertext. So
    without this, an API write skips the check an ORM or form write gets and the
    duplicate surfaces as an ``IntegrityError`` from the constraint: a 500 where
    the client should have had a 400 naming the field.

    Carries DRF's own message rather than one of its own, so a client that
    already handles a unique violation on a plain field handles this one
    unchanged, and no new string needs translating.
    """

    requires_context = True
    message = UniqueValidator.message

    def __init__(self, model_field):
        self.model_field = model_field

    def __call__(self, value, serializer_field):
        if value is None:
            return
        # The row being updated is not a duplicate of itself. DRF hangs the
        # instance on the parent serializer, which is where its own
        # UniqueValidator reads it from too.
        instance = getattr(serializer_field.parent, "instance", None)
        exclude_pk = getattr(instance, "pk", None)
        digest = self.model_field.index_digest(value)
        if self.model_field.index_conflict(digest, exclude_pk=exclude_pk):
            raise DrfValidationError(self.message, code="unique")


class EncryptionSerializerMixin:
    """Render undecryptable encrypted fields as a structured marker.

    On a lenient read, a decrypt failure yields an ``UndecryptableValue``
    sentinel that stringifies to a fallback label — safe and legible for a human
    UI, but a machine API consumer cannot tell that string from real plaintext.
    This mixin consults the per-instance ``_encryption_suite_errors`` map (populated
    when the fields were accessed during ``super().to_representation``) and, for
    each failed field, sets the value to ``null`` and records its stable slug
    under a ``encryption_suite_errors`` key, e.g.::

        {"id": 10, "notes": null,
         "encryption_suite_errors": {"notes": {"code": "field_decryption_failed"}}}

    This keeps the field type stable (``string | null``), is unambiguous to a
    machine, and allows partial success — a list still returns its good rows
    with only the failed fields flagged. Successful fields are untouched.

    Encrypted *file* fields get the same marker, but they fail at a different
    moment: serializing one renders its storage name without reading the blob,
    so nothing has failed yet. What fails is ``EncryptedFieldFile.probe()``,
    which opens storage and reads a byte. The slug is whatever the probe caught,
    so a file whose data key is gone reports ``missing_dek``. By default the
    mixin reports only a probe that already ran — free, since the result is
    cached on the file, and what a detail view has usually done already. Set
    ``PROBE_ENCRYPTED_FILES = True`` to probe every encrypted file field being
    serialized: one storage open per file per row, which a detail endpoint can
    afford and a list endpoint generally cannot. A display-name failure is not
    reported under the file field; it is the companion column's own failure and
    is reported under that field when it is serialized.

    The read path matches serializer field names to model attribute names (the
    common ``ModelSerializer`` case) and does not follow ``source``, so a renamed
    field is not marked. The write path in :meth:`get_fields` does follow
    ``source``: it resolves one field it was handed, where the read path starts
    from the failures and would have to search the serializer for each.
    """

    ENCRYPTION_ERRORS_KEY = "encryption_suite_errors"
    PROBE_ENCRYPTED_FILES = False

    def get_fields(self):
        """Correct the write-side checks DRF infers from an encrypted model field.

        Writes, where the read half of this mixin is about reads:

        * A field whose plaintext is held unique over a blind index gets the
          check ``ModelSerializer`` would have added had the model field
          reported ``unique``. See :class:`BlindIndexUniqueValidator`.
        * An encrypted file field limits the uploaded filename to the
          display-name column, which is where that name is kept — the same
          limit its form field applies. ``ModelSerializer`` copies the file
          column's ``max_length``, which bounds the opaque stored path, not the
          name a client sends. Only that inferred value is replaced, so a
          serializer field declared with its own ``max_length`` keeps it.
        """
        from django.core.exceptions import FieldDoesNotExist

        from ..fields import _EncryptedFileFieldBase

        fields = super().get_fields()
        model = getattr(getattr(self, "Meta", None), "model", None)
        if model is None:
            return fields
        for name, serializer_field in fields.items():
            if serializer_field.read_only:
                continue
            source = serializer_field.source or name
            if "." in source or source == "*":
                continue
            try:
                model_field = model._meta.get_field(source)
            except FieldDoesNotExist:
                continue
            if isinstance(model_field, _EncryptedFileFieldBase):
                if getattr(serializer_field, "max_length", None) == model_field.max_length:
                    serializer_field.max_length = model_field._display_name_max_length()
                continue
            if not _holds_unique_blind_index(model_field):
                continue
            if any(isinstance(validator, BlindIndexUniqueValidator) for validator in serializer_field.validators):
                continue
            serializer_field.validators = [
                *serializer_field.validators,
                BlindIndexUniqueValidator(model_field),
            ]
        return fields

    def to_representation(self, instance):
        data = super().to_representation(instance)
        errors = dict(getattr(instance, "_encryption_suite_errors", None) or {})
        errors.update(self._file_errors(instance, data))
        if not errors:
            return data
        marker = {}
        for field_name, error in errors.items():
            if field_name in data:
                data[field_name] = None
                marker[field_name] = {"code": getattr(error, "code", "")}
        if marker:
            data[self.ENCRYPTION_ERRORS_KEY] = marker
        return data

    def _file_errors(self, instance, data) -> dict:
        """The probe failure of each encrypted file field in *data*, by attname.

        Reads ``decryption_error`` rather than ``is_undecryptable``, which is
        also true when the display name failed — a failure the value path
        already reports under the display-name field.
        """
        from ..fields import _EncryptedFileFieldBase

        meta = getattr(type(instance), "_meta", None)
        if meta is None:
            return {}
        errors = {}
        for field in meta.concrete_fields:
            if not isinstance(field, _EncryptedFileFieldBase) or field.attname not in data:
                continue
            fieldfile = getattr(instance, field.attname)
            if self.PROBE_ENCRYPTED_FILES:
                fieldfile.probe()
            if fieldfile.decryption_error is not None:
                errors[field.attname] = fieldfile.decryption_error
        return errors
