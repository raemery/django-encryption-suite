"""
Data key rotation — the state machine behind ``reencrypt_data``.

A rotation moves one silo's data for one purpose onto new key material, then
swaps that material in as the data key's own. In order, and not interchangeable:

1. **Open.** Generate the incoming keyset under the silo's current key encryption
   key, outside any transaction, so a failed wrap leaves no trace. Then, in one
   transaction, raise the fence (status ``reencrypting``), write the rotation
   row, and record ``rotation_started``.
2. **Wait** a full ``DEK_CACHE_TTL`` plus a margin, measured from the rotation
   row's ``started_at``. Other processes may still hold the old primitive; once
   it expires they cannot load another, because the fence refuses it. A resumed
   run sleeps only the remainder.
3. **Build the worklist** — only now, because the fence stops every encrypted
   write for the purpose, so the list stays complete for as long as it holds.
   An incomplete one is discarded and rebuilt, never continued.
4. **Sweep** every outstanding item from the old keyset to the incoming one,
   each in its own transaction. A row that will not convert is recorded and
   skipped; the sweep carries on to the end.
5. **Swap** — only when the worklist is complete and every item converted, both
   re-read under the row lock. Overwriting the keyset while anything is still
   wrapped under it crypto-shreds that data with no way back.

``--abort`` walks the converted items backwards onto the old keyset, then
abandons the rotation. Every step is resumable by rerunning the command.

Values are never staged: the worklist records what to do and what was done. How
one item moves between keysets lives in :mod:`encryption_suite.rotation_items`.
"""

from __future__ import annotations

import contextlib
import math
import time
from dataclasses import dataclass
from datetime import timedelta

from django.apps import apps
from django.core.exceptions import FieldDoesNotExist
from django.db import transaction
from django.utils import timezone

from . import lifecycle, user_context
from ._internal import iter_rows, optional_log_field
from ._logging import get_logger
from .conf import enc_settings
from .engine import EncryptionEngine, ensure_kek_provisioned
from .fields import aad_attnames, describe_aad_column
from .models import DataEncryptionKey, DekRotation, DekRotationWorkItem, recorded_identity
from .rotation_items import DONE, GONE, ItemConverter
from .rotation_targets import rows_for_silo
from .silo_ref import SiloRef, silo_filter

logger = get_logger(__name__)

#: Seconds added to ``DEK_CACHE_TTL`` before conversion starts, covering the
#: commit reaching every process and the clocks they measure the TTL by.
WAIT_MARGIN_SECONDS = 5
#: Targets found gone one after another before a pass stops instead of closing
#: them. Deletes are not fenced, so a few are an ordinary tidy-up; a long run of
#: them is a wrong schema or a wrong database, and closing those items would let
#: the swap destroy the key their rows are still under.
MAX_CONSECUTIVE_MISSES = 20
_BATCH = 1000

# Indirection so a test can skip the wait without patching the time module.
_sleep = time.sleep

# How a run left one silo's purpose.
OUTCOME_SKIPPED = "skipped"
OUTCOME_SWAPPED = "swapped"
OUTCOME_OUTSTANDING = "outstanding"
OUTCOME_ABANDONED = "abandoned"
OUTCOME_ROLLBACK_OUTSTANDING = "rollback_outstanding"
OUTCOME_STOPPED = "stopped"

# Rows of a crypto backend's describe_config() that describe the *other*
# purpose's primitive, so a rotation names only the template its own key comes
# from. A row not listed here — a cipher both purposes share — is kept.
_OTHER_PURPOSE_CONFIG = {
    DataEncryptionKey.PURPOSE_FIELD: frozenset({"file_streaming_aead", "segment_size"}),
    DataEncryptionKey.PURPOSE_FILE: frozenset({"field_aead"}),
    # An index key comes from no backend template at all, so every row a backend
    # describes is about something else.
    DataEncryptionKey.PURPOSE_INDEX: frozenset({"field_aead", "file_streaming_aead", "segment_size"}),
}

# The states an outcome leaves the fence up in.
FENCED_OUTCOMES = frozenset({OUTCOME_OUTSTANDING, OUTCOME_ROLLBACK_OUTSTANDING, OUTCOME_STOPPED})


@dataclass
class Outcome:
    silo_ref: SiloRef
    purpose: str
    state: str
    #: Skip reason, refusal, or stop explanation; empty on a clean result.
    detail: str = ""
    #: Items moved this run — forward on a sweep, backward on a rollback.
    converted: int = 0
    #: Items still outstanding when the run left this purpose.
    outstanding: int = 0


def wait_seconds() -> int:
    """The idle wait between raising the fence and building the worklist."""
    return int(enc_settings.DEK_CACHE_TTL) + WAIT_MARGIN_SECONDS


def key_conversion(purpose: str, crypto_backend: str, algorithm: str, configured) -> str:
    """What a rotation changes about how a data key is generated, or ``""`` when the key is current.

    *crypto_backend* and *algorithm* are what the data key row recorded;
    *configured* is the crypto backend that makes the incoming key. A key whose
    backend or algorithm differs from what *configured* generates now for
    *purpose* is outdated, and the answer names each move —
    ``backend tink -> cryptography, algorithm AES256_GCM -> CHACHA20_POLY1305``.
    A blank recorded value proves nothing current, so it counts as a move from
    ``unrecorded``. An index key is HMAC key material whatever the backend and
    its options, so it is never outdated by them.

    ASCII ``->``: the command prints it, and a Windows console piped to a file
    encodes as cp1252, which has no arrow.
    """
    if purpose == DataEncryptionKey.PURPOSE_INDEX:
        return ""
    moves = []
    if crypto_backend != configured.backend_id:
        moves.append(f"backend {crypto_backend or 'unrecorded'} -> {configured.backend_id}")
    current = configured.algorithm_id(purpose)
    if algorithm != current:
        moves.append(f"algorithm {algorithm or 'unrecorded'} -> {current}")
    return ", ".join(moves)


def outstanding_items(dek):
    """Items still on the old keyset, in the order the report prints them."""
    return DekRotationWorkItem.objects.filter(dek=dek, converted_at__isnull=True).order_by("pk")


def converted_items(dek):
    """Items on the incoming keyset — what a rollback has to reverse."""
    return DekRotationWorkItem.objects.filter(dek=dek, converted_at__isnull=False).order_by("pk")


def aad_columns_for(model_label: str, object_pk: str, field_name: str):
    """``[(column, value)]`` for the columns a field binds on a row, or ``[]`` if it binds none or is gone."""
    try:
        model = apps.get_model(model_label)
        field = model._meta.get_field(field_name)
    except (LookupError, ValueError, FieldDoesNotExist):
        return []
    cols = aad_attnames(field)
    if not cols:
        return []
    values = model._base_manager.filter(pk=model._meta.pk.to_python(object_pk)).values(*cols).first()
    if values is None:
        return []
    return [(col, values[col]) for col in cols if col != model._meta.pk.attname]


def render_aad(columns, *, show_values: bool) -> str:
    """``col=<populated>,col=<empty>`` — or the values themselves when asked."""
    return ",".join(f"{col}={describe_aad_column(value, show_value=show_values)}" for col, value in columns)


class Rotator:
    """Runs rotations for one invocation of ``reencrypt_data``.

    *write* receives operator output a line at a time, as ``write(text, style)``
    where *style* is ``None``, ``"success"``, ``"warning"`` or ``"error"``.
    """

    def __init__(self, *, engine, adapter, resolution, os_login_user: str, write):
        self.engine = engine
        self.adapter = adapter
        self.resolution = resolution
        self.os_login_user = os_login_user
        self.write = write
        self.items = ItemConverter(os_login_user)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(
        self,
        silo_ref: SiloRef,
        purpose: str,
        silo=None,
        *,
        abort=False,
        abort_on_unconvertible=False,
    ) -> Outcome:
        """Open, resume, or unwind the rotation for the *purpose* key of *silo_ref*."""
        dek = DataEncryptionKey.objects.select_related("kek").filter(**silo_filter(silo_ref), purpose=purpose).first()
        if dek is None:
            return Outcome(silo_ref, purpose, OUTCOME_SKIPPED, "no data encryption key for this purpose")
        rotation = DekRotation.objects.select_related("kek").filter(dek=dek).first()

        if dek.status == lifecycle.STATUS_REENCRYPTING:
            if rotation is None:
                return Outcome(silo_ref, purpose, OUTCOME_SKIPPED, "the key is fenced but has no rotation row")
            # A rerun follows the flag: an interrupted rollback reads like an
            # interrupted sweep otherwise, and would convert forward again.
            if abort or rotation.rolling_back:
                return self._rollback(dek, rotation, silo, reason="")
            return self._forward(dek, rotation, silo, abort_on_unconvertible=abort_on_unconvertible)

        if abort:
            return Outcome(silo_ref, purpose, OUTCOME_SKIPPED, "no rotation is open")
        # `active` is the rule for opening a rotation, not for continuing one:
        # the fenced case above is where a resume lands.
        if dek.status != lifecycle.STATUS_ACTIVE:
            return Outcome(silo_ref, purpose, OUTCOME_SKIPPED, f"data encryption key is {dek.status}")
        if rotation is not None:
            return Outcome(silo_ref, purpose, OUTCOME_SKIPPED, "a rotation row exists but the key is not fenced")
        refusal = self.open_refusal(dek)
        if refusal:
            return Outcome(silo_ref, purpose, OUTCOME_SKIPPED, refusal)

        opened = self._open(dek)
        if opened is None:
            return Outcome(silo_ref, purpose, OUTCOME_SKIPPED, "another run opened a rotation for this key first")
        dek, rotation = opened
        return self._forward(dek, rotation, silo, abort_on_unconvertible=abort_on_unconvertible)

    def open_refusal(self, dek) -> str:
        """Why a rotation cannot open on *dek*, or ``""``.

        The outgoing key is read through what its row recorded, so a rotation
        is also how a silo moves onto the configured backend. What refuses is a
        row that cannot be read at all: a KMS no block names, or a backend this
        installation cannot build. Checked before the fence, because a failure
        caught at the first unwrap costs a fenced silo and an abort.
        """
        from .conf import kms_block
        from .exceptions import EncryptionError
        from .registry import get_crypto_backend_by_id

        if kms_block(dek.kek.key_store) is None:
            return f"on key store '{dek.kek.key_store}', which no KMS_KEY_STORES block names"
        if dek.purpose != DataEncryptionKey.PURPOSE_INDEX and dek.crypto_backend:
            try:
                backend = get_crypto_backend_by_id(dek.crypto_backend)
            except EncryptionError:
                backend = None
            if backend is None:
                return f"made by crypto backend '{dek.crypto_backend}', which this installation cannot build"
        return ""

    def key_conversion(self, dek) -> str:
        """What rotating *dek* changes about how its key is generated; see :func:`key_conversion`."""
        return key_conversion(dek.purpose, dek.crypto_backend, dek.algorithm, self.engine.crypto_backend)

    # ------------------------------------------------------------------
    # Open, wait, build
    # ------------------------------------------------------------------

    def _open(self, dek):
        """Mint the incoming keyset, then raise the fence. ``None`` if another run beat us."""
        silo_ref, purpose = dek.silo_ref, dek.purpose
        # The incoming key goes to the store the settings give the key's set.
        kek_id, created_kek = ensure_kek_provisioned(
            self.engine.new_key_kms_adapter(silo_ref),
            self.engine.new_key_kek_provisioner(silo_ref),
            silo_ref,
            os_login_user=self.os_login_user,
        )
        keyset, metadata = self.engine._new_wrapped_keyset(silo_ref, purpose, kek_id)
        conversion = self.key_conversion(dek)

        with transaction.atomic():
            locked = DataEncryptionKey.objects.select_for_update().select_related("kek").get(pk=dek.pk)
            if locked.status != lifecycle.STATUS_ACTIVE or DekRotation.objects.filter(dek=locked).exists():
                return None
            user, os_user_row, _ip_row = recorded_identity(os_login_user=self.os_login_user)
            kek_row = self.engine._kek_row(
                metadata, created_kek, trigger=lifecycle.TRIGGER_AUTOMATED, os_login_user=self.os_login_user
            )
            rotation = DekRotation.objects.create(
                dek=locked,
                encrypted_keyset=keyset,
                kek=kek_row,
                kek_key_version=metadata.kek_key_version,
                # The backend that made the incoming material, so the swap labels
                # it right even if CRYPTO_BACKEND changes before a resumed run.
                crypto_backend=(
                    "" if purpose == DataEncryptionKey.PURPOSE_INDEX else self.engine.crypto_backend.backend_id
                ),
                algorithm=self.engine._algorithm_for(purpose),
                started_at=timezone.now(),
                user_id=user,
                os_user=os_user_row,
            )
            locked.record_event(
                lifecycle.EVENT_ROTATION_STARTED,
                trigger=lifecycle.TRIGGER_AUTOMATED,
                os_login_user=self.os_login_user,
            )
        EncryptionEngine.invalidate_cache(silo_ref)

        # WARNING: this fences the silo's data for the purpose, and heads toward
        # the swap that overwrites the key material the data is under now.
        logger.warning(
            "A data key rotation started; encrypted reads and writes of this silo's data for this "
            'purpose are fenced until every row is on one keyset. event=%s silo="%s" purpose=%s kek="%s" %s',
            lifecycle.EVENT_ROTATION_STARTED,
            silo_ref,
            purpose,
            kek_row.kek_resource_name,
            user_context.identity_tail(os_login_user=self.os_login_user),
        )
        if purpose == DataEncryptionKey.PURPOSE_INDEX:
            # No backend template to name: an index key is HMAC key material,
            # deliberately independent of CRYPTO_BACKEND so a change of backend
            # leaves a silo's stored digests findable.
            self.write(
                f"Opened: {silo_ref} [{purpose}] — the incoming key is fresh index key material, which "
                f"no crypto backend produces. Every indexed value is decrypted to recompute its digest.",
                None,
            )
        else:
            algorithm = ", ".join(
                f"{key}={value}"
                for key, value in self.engine.crypto_backend.describe_config()
                if key not in _OTHER_PURPOSE_CONFIG[purpose]
            )
            self.write(
                f"Opened: {silo_ref} [{purpose}] — the incoming key uses the configured backend's current "
                f"template ({self.engine.crypto_backend.describe()}{': ' + algorithm if algorithm else ''})"
                f"{f', converting {conversion}' if conversion else ''}.",
                None,
            )
        return locked, rotation

    def _wait(self, rotation) -> None:
        """Sleep out whatever remains of the wait, measured from ``started_at``."""
        until = rotation.started_at + timedelta(seconds=wait_seconds())
        remaining = (until - timezone.now()).total_seconds()
        if remaining <= 0:
            return
        self.write(
            f"Waiting {math.ceil(remaining)}s for keys cached by other processes to expire before converting. "
            "The silo is fenced meanwhile; this is not a hang, and interrupting it is safe — a rerun waits "
            "out the rest.",
            "warning",
        )
        _sleep(remaining)

    def _build_worklist(self, dek, rotation, silo) -> None:
        """Enumerate every item to convert, then mark the list complete — last."""
        delete_worklist(dek)
        purpose = dek.purpose
        count = 0
        for target in self.resolution.for_purpose(purpose, dek.key_set):
            queryset = rows_for_silo(self.adapter, target, dek.silo_ref.uid, silo)
            for name in target.names_for(purpose, dek.key_set):
                batch = []
                for pk in _iter_pks(queryset.filter(**{f"{name}__isnull": False})):
                    batch.append(
                        DekRotationWorkItem(dek=dek, model_label=target.label, object_pk=str(pk), field_name=name)
                    )
                    if len(batch) >= _BATCH:
                        DekRotationWorkItem.objects.bulk_create(batch)
                        count += len(batch)
                        batch = []
                if batch:
                    DekRotationWorkItem.objects.bulk_create(batch)
                    count += len(batch)
        rotation.worklist_complete = True
        rotation.save(update_fields=["worklist_complete"])
        self.write(f"Worklist: {dek.silo_ref} [{purpose}] — {count} item(s) to convert.", None)

    @contextlib.contextmanager
    def _keysets(self, dek, rotation):
        """Hold both of the silo's primitives for the run, and drop them on every exit.

        Bypasses the primitive cache and the fence check, which would refuse a
        fenced key — the one this needs.
        """
        held = {}
        try:
            held["old"] = self.engine._unwrap_primitive(
                dek.purpose,
                dek.encrypted_keyset,
                dek.kek,
                dek.kek_key_version,
                dek.silo_ref,
                backend_id=dek.crypto_backend,
            )
            held["new"] = self.engine._unwrap_primitive(
                dek.purpose,
                rotation.encrypted_keyset,
                rotation.kek,
                rotation.kek_key_version,
                dek.silo_ref,
                backend_id=rotation.crypto_backend,
            )
            yield held["old"], held["new"]
        finally:
            held.clear()

    # ------------------------------------------------------------------
    # Forward, swap
    # ------------------------------------------------------------------

    def _forward(self, dek, rotation, silo, *, abort_on_unconvertible) -> Outcome:
        silo_ref, purpose = dek.silo_ref, dek.purpose
        self._wait(rotation)
        if not rotation.worklist_complete:
            self._build_worklist(dek, rotation, silo)

        with self._keysets(dek, rotation) as (old, new):
            converted, stopped = self._sweep(dek, old, new, forward=True, silo=silo)
            outstanding = outstanding_items(dek).count()
            if stopped:
                return Outcome(silo_ref, purpose, OUTCOME_STOPPED, stopped, converted, outstanding)
            if outstanding and abort_on_unconvertible:
                self.write(
                    f"{silo_ref} [{purpose}]: {outstanding} item(s) could not be converted; "
                    "--abort-on-unconvertible is set, so the rotation is being undone.",
                    "warning",
                )
                return self._unwind(dek, rotation, old, new, silo, reason=lifecycle.REASON_UNCONVERTIBLE_ROWS)

        if outstanding:
            return Outcome(silo_ref, purpose, OUTCOME_OUTSTANDING, "", converted, outstanding)
        refusal = self._swap(dek, converted)
        if refusal:
            return Outcome(silo_ref, purpose, OUTCOME_OUTSTANDING, refusal, converted, outstanding_items(dek).count())
        return Outcome(silo_ref, purpose, OUTCOME_SWAPPED, "", converted, 0)

    def _swap(self, dek, converted: int) -> str:
        """Put the incoming keyset in place. Returns a refusal, or ``""`` on success.

        *converted* is what this run moved, and is reported on the closing line
        as ``reencrypted=``: the rotation's own lines are the only record of how
        much data a rotation re-encrypted, because moving a value between keysets
        never goes through the engine's decrypt path that ``LOG_DECRYPTS``
        records.

        Both preconditions are re-read inside this transaction, under the row
        lock, so a second process or a resumed run cannot convert the last item
        concurrently with a swap that already decided it was done. The data key
        is locked before the rotation row — the order the rewrap pass takes them
        in, so the two cannot deadlock.
        """
        with transaction.atomic():
            locked = DataEncryptionKey.objects.select_for_update().get(pk=dek.pk)
            rotation = DekRotation.objects.select_for_update().select_related("kek").filter(dek=locked).first()
            if rotation is None or locked.status != lifecycle.STATUS_REENCRYPTING:
                return "the rotation was closed by another run"
            if not rotation.worklist_complete:
                return "the worklist was never finished"
            if outstanding_items(locked).exists():
                return "items are still outstanding"
            locked.encrypted_keyset = rotation.encrypted_keyset
            locked.kek = rotation.kek
            locked.kek_key_version = rotation.kek_key_version
            locked.crypto_backend = rotation.crypto_backend
            locked.algorithm = rotation.algorithm
            locked.key_material_last_generated_at = timezone.now()
            locked.dek_key_version += 1
            # Moved as well as the version, because the rewrap pass uses it to
            # tell that the material it unwrapped went stale: a swap landing
            # between its unwrap and its lock must make it skip.
            locked.reencryption_count += 1
            locked.save(
                update_fields=[
                    "encrypted_keyset",
                    "kek",
                    "kek_key_version",
                    "crypto_backend",
                    "algorithm",
                    "key_material_last_generated_at",
                    "dek_key_version",
                    "reencryption_count",
                    "updated_at",
                ]
            )
            rotation.delete()
            locked.record_event(
                lifecycle.EVENT_ROTATED,
                trigger=lifecycle.TRIGGER_AUTOMATED,
                os_login_user=self.os_login_user,
                status=lifecycle.STATUS_ACTIVE,
            )
        EncryptionEngine.invalidate_cache(locked.silo_ref)
        delete_worklist(locked)
        # WARNING: the old key material was overwritten — destroyed, as far as
        # this deployment is concerned.
        logger.warning(
            "A data key rotation finished; the old key material was overwritten and the silo's data "
            'for this purpose is readable again. event=%s silo="%s" purpose=%s dek_key_version=%d reencrypted=%d %s',
            lifecycle.EVENT_ROTATED,
            locked.silo_ref,
            locked.purpose,
            locked.dek_key_version,
            converted,
            user_context.identity_tail(os_login_user=self.os_login_user),
        )
        return ""

    # ------------------------------------------------------------------
    # Rollback, abandon
    # ------------------------------------------------------------------

    def _rollback(self, dek, rotation, silo, *, reason: str) -> Outcome:
        if not converted_items(dek).exists():
            # Nothing reached the incoming keyset — an interrupted wait or build,
            # or a sweep that converted nothing — so there is nothing to walk
            # back and no need to reach the KMS.
            return self._abandon(dek, reason=reason, converted=0)
        with self._keysets(dek, rotation) as (old, new):
            return self._unwind(dek, rotation, old, new, silo, reason=reason)

    def _unwind(self, dek, rotation, old, new, silo, *, reason: str) -> Outcome:
        """Walk converted items back onto the old keyset, then abandon if none remain."""
        silo_ref, purpose = dek.silo_ref, dek.purpose
        if not rotation.rolling_back:
            # Written before the first reverse conversion: a rollback clears
            # converted_at as it goes, so without the flag an interrupted one
            # reads as an interrupted sweep.
            rotation.rolling_back = True
            rotation.save(update_fields=["rolling_back"])
        reversed_count, stopped = self._sweep(dek, new, old, forward=False, silo=silo)
        remaining = converted_items(dek).count()
        if stopped:
            return Outcome(silo_ref, purpose, OUTCOME_STOPPED, stopped, reversed_count, remaining)
        if remaining:
            return Outcome(silo_ref, purpose, OUTCOME_ROLLBACK_OUTSTANDING, "", reversed_count, remaining)
        return self._abandon(dek, reason=reason, converted=reversed_count)

    def _abandon(self, dek, *, reason: str, converted: int) -> Outcome:
        """Drop the rotation and lower the fence, once nothing is left converted."""
        with transaction.atomic():
            locked = DataEncryptionKey.objects.select_for_update().get(pk=dek.pk)
            rotation = DekRotation.objects.select_for_update().filter(dek=locked).first()
            if rotation is None:
                return Outcome(dek.silo_ref, dek.purpose, OUTCOME_SKIPPED, "the rotation was closed by another run")
            if converted_items(locked).exists():
                return Outcome(
                    dek.silo_ref,
                    dek.purpose,
                    OUTCOME_ROLLBACK_OUTSTANDING,
                    "items are still on the incoming keyset",
                    converted,
                    converted_items(locked).count(),
                )
            rotation.delete()
            locked.record_event(
                lifecycle.EVENT_ROTATION_ABANDONED,
                trigger=lifecycle.TRIGGER_AUTOMATED,
                os_login_user=self.os_login_user,
                reason=reason,
                status=lifecycle.STATUS_ACTIVE,
            )
        EncryptionEngine.invalidate_cache(locked.silo_ref)
        delete_worklist(locked)
        # WARNING: the incoming key material is destroyed with the rotation row.
        logger.warning(
            "A data key rotation was abandoned; the incoming key material was discarded and the silo's "
            "data for this purpose is readable again on its old key. event=%s reason=%s "
            'silo="%s" purpose=%s moved_back=%d %s',
            lifecycle.EVENT_ROTATION_ABANDONED,
            reason or "none",
            locked.silo_ref,
            locked.purpose,
            converted,
            user_context.identity_tail(os_login_user=self.os_login_user),
        )
        # The detail carries the reason slug, so a caller can tell an operator's
        # abort from an unattended unwind without a second field.
        return Outcome(dek.silo_ref, dek.purpose, OUTCOME_ABANDONED, reason, converted, 0)

    # ------------------------------------------------------------------
    # The sweep
    # ------------------------------------------------------------------

    def _scope(self, dek, silo):
        """``{model label: that silo's rows}`` — the filter the worklist was built with.

        Conversions read and write through it, so a row that has left the silo
        since the build reads as gone rather than being converted onto a key it
        no longer belongs under, and one that arrived since is left alone. A
        model whose rows need the silo object where the run has none — an
        ``--abort`` that never resolved one — maps to ``None``, and the
        conversion falls back to the row's own identity.
        """
        scope = {}
        for target in self.resolution.for_purpose(dek.purpose, dek.key_set):
            try:
                scope[target.label] = rows_for_silo(self.adapter, target, dek.silo_ref.uid, silo)
            except Exception:
                scope[target.label] = None
        return scope

    def _sweep(self, dek, source, target, *, forward: bool, silo=None) -> tuple[int, str]:
        """Convert every item not yet in the target state. Returns ``(converted, stop reason)``.

        A target that is gone closes its item — nothing remains under the source
        keyset — but only once a later item shows this connection can still see
        rows. A long run of misses stops the pass with those items left open.
        """
        items = DekRotationWorkItem.objects.filter(dek=dek, converted_at__isnull=forward)
        scope = self._scope(dek, silo)
        converted = 0
        misses: list = []
        # An index rotation derives each digest from the plaintext, so it needs
        # the silo's field key to read values the key it is rotating cannot.
        # Resolved once for the sweep rather than per row, and only where it is
        # needed: the other two purposes read with the keyset they convert.
        reader = None
        if dek.purpose == DataEncryptionKey.PURPOSE_INDEX:
            reader = self.engine._get_cached_aead(dek.silo_ref)
        for item in iter_rows(items):
            result = self.items.convert(
                item, source, target, forward=forward, purpose=dek.purpose, scope=scope, reader=reader
            )
            if result == GONE:
                misses.append(item)
                if len(misses) > MAX_CONSECUTIVE_MISSES:
                    return converted, (
                        f"{len(misses)} targets in a row no longer exist, which points at the wrong database "
                        "or schema rather than deleted rows; stopped with them left open"
                    )
                continue
            for missed in misses:
                self.items.close_gone(missed, forward=forward)
            misses = []
            if result == DONE:
                converted += 1
            else:
                self._record_failure(dek, item, result, forward=forward)
        for missed in misses:
            self.items.close_gone(missed, forward=forward)
        if dek.purpose == DataEncryptionKey.PURPOSE_FILE:
            self.items.settle_pending(dek)
        return converted, ""

    def _record_failure(self, dek, item, code: str, *, forward: bool) -> None:
        item.failure_code = code
        item.save(update_fields=["failure_code"])
        # One line per row, carrying the AAD columns under LOG_AAD_VALUES: which
        # bound column moved is usually the whole diagnosis.
        logger.error(
            "A row could not be %s and stays on its current keyset; the rotation cannot finish until it is "
            'repaired or the rotation is aborted. error_code=%s silo="%s" purpose=%s model=%s pk=%s target=%s%s %s',
            "converted" if forward else "reversed",
            code,
            dek.silo_ref,
            dek.purpose,
            item.model_label,
            item.object_pk,
            item.field_name,
            # Omitted rather than empty for a field that binds no AAD columns: an
            # empty field in front of an operator says nothing.
            optional_log_field(
                "aad",
                render_aad(
                    aad_columns_for(item.model_label, item.object_pk, item.field_name),
                    show_values=bool(enc_settings.LOG_AAD_VALUES),
                ),
            ),
            user_context.identity_tail(os_login_user=self.os_login_user),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def delete_worklist(dek) -> None:
    """Delete *dek*'s worklist in batches. It is the largest table here."""
    while True:
        pks = list(DekRotationWorkItem.objects.filter(dek=dek).values_list("pk", flat=True)[:_BATCH])
        if not pks:
            return
        DekRotationWorkItem.objects.filter(pk__in=pks).delete()


def _iter_pks(queryset):
    """Yield the primary keys of *queryset* a page at a time, keyset-paginated."""
    last = None
    while True:
        page = queryset.order_by("pk")
        if last is not None:
            page = page.filter(pk__gt=last)
        pks = list(page.values_list("pk", flat=True)[:_BATCH])
        if not pks:
            return
        yield from pks
        last = pks[-1]
