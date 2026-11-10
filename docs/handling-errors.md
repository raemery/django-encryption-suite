# Handling encryption_suite errors

django-encryption-suite degrades errors **leniently** by design — not to hide
failures, but to strip the harmful packaging around them. Three goals drive it:

1. **Users** never see untranslated, technical strings that could leak sensitive
   or infrastructure detail — only a generic, translated "there was a problem."
2. **Admins** get clean, actionable log lines with **no tracebacks** (this is a
   dependency you don't maintain — a stack trace into its internals is noise).
3. **Escalation**: the log carries enough (operator detail + a stable
   [error-code slug](error-codes.md)) to fix it yourself or report a genuine bug.

This guide shows how to handle those errors in two places: **in your code** and
at your **API boundary**. The [Error codes](error-codes.md) reference lists
every error code and its meaning.

## 1. In your code

Every failure is a [`EncryptionError`](error-codes.md) subclass (itself a
`ValueError`). Catch the base to handle them all; branch on subclasses or
`exc.code` when you need to:

```python
from encryption_suite.exceptions import EncryptionError

try:
    obj.save()  # encrypts in pre_save — may reach the KMS
except EncryptionError as exc:
    messages.error(request, str(exc))   # generic, translated, user-safe
    # exc.code is the stable slug; operator detail is already in the logs
```

**Reads degrade, they don't raise** (in the default *lenient* mode). In the admin, a
value the viewer cannot decrypt, such as another user's value in a [user-specific key
set](user-specific-silos.md), renders as the fallback label, and an `EncryptedJSONField`
renders `{}`. Accessing
an encrypted field whose value can't be decrypted returns an
`UndecryptableValue` sentinel — falsy, and it stringifies to a translated
fallback label, so a template renders it directly. Detect it **by type**, never
by comparing the string (a real value could equal the fallback text):

```python
from encryption_suite import is_undecryptable

if is_undecryptable(obj.notes):
    ...  # decryption failed; obj.notes is the sentinel, not real data
```

Need a read to **raise** instead of degrade (e.g. an export that must not emit
placeholders)? Use strict mode:

```python
from encryption_suite import strict_mode

with strict_mode():
    value = obj.notes   # raises EncryptionError instead of returning a sentinel
```

**Inside a form, a failure is a form error.** Three failures happen while a form
validates, before any code of yours can catch them, and each arrives on the form
with the generic message rather than as a `500`:

- **The duplicate check** on a `unique` or `unique_in_silo` blind-indexed column.
  The check needs the silo's index key, which a first write may have to create
  through the KMS. A failure there becomes a form-wide error coded with the slug.
- **A lookup on a blind-indexed column**, such as `filter(email=...)` run from a
  form's `clean()`. This covers code you didn't write: allauth's sign-in and
  sign-up forms, and Django's auth backend when a form calls it. The error raised
  is the original `EncryptionError` subclass and also a Django `ValidationError`,
  so the form shows `str(exc)`. `isinstance` checks, `exc.code`, `exc.detail` and
  the [DRF](working-with-django-rest-framework.md#errors) status all match the original. Outside a
  form it propagates like any other `EncryptionError`.

- **A string method on a value that failed to decrypt.** A lenient read returns
  the `UndecryptableValue` sentinel, and code that calls `value.lower()`,
  `value.strip()` or any other public `str` method on it gets the sentinel's
  underlying error, raised the same way. allauth does this when signing a user
  in: it finds the user through the blind index, then compares
  `user.email.lower()`. Displaying the sentinel is unchanged: `str()`,
  templates and `is_undecryptable()` work as before.

In every case the place that raised the error has already logged it once, with
its code.

A DEK that has been scheduled for deletion (`dek_deletion_scheduled`) or deleted
(`dek_deleted`) is just another `EncryptionError`: a lenient read of such a
silo's fields degrades to the sentinel, and a write to a scheduled silo raises
(a write to a *deleted* silo instead revives the key when `KEY_AUTO_PROVISION` is
on). No special handling is needed beyond catching `EncryptionError`.

### While a data key is being rotated

A silo whose data key is being rotated by
[`reencrypt_data`](key-rotation.md#rotating-a-data-encryption-key) raises
`DekReencryptionInProgressError` (`dek_reencryption_in_progress`) for that silo
and purpose. A read degrades to the sentinel like any other failure, and a write
raises — so a form save fails with the same generic message a user sees for any
key problem. This is the one failure that clears on its own, when the rotation
swaps or is rolled back, which is why retryability is decided from the **error's
type**, never from the fallback string: check
`isinstance(obj.encryption_suite_errors.get("notes"), DekReencryptionInProgressError)`
(or its `code`) where you want to say "try again later" rather than "this is
broken". The message itself makes no promise about when, because a rotation that
ends with rows it could not convert leaves the fence up until an operator acts.

A rotation costs a tenant the following while it runs:

- **Encrypted reads and writes both stop** for the purpose being rotated;
  unencrypted columns are untouched, and the other purpose keeps working.
- **A field rotation darkens file names too.** A file's display name is field
  data, so a file listing shows fallbacks while the blobs themselves stay
  readable, and a download during a field rotation still serves the file — as
  `download.bin`, because the fallback is empty as far as a filename is
  concerned. A preview that picks image or PDF handling from the name's
  extension (`obj.<field>.kind`) finds none, and treats the file as unsupported.
  The blob itself is untouched by a field rotation: `download.bin` is the real
  file, and renaming it with its original extension opens it normally.
- **The window** is the sweep plus the idle wait before it (`DEK_CACHE_TTL` plus
  a few seconds), once per purpose. A run that ends with rows outstanding keeps it
  in force until an operator reruns or aborts.
- **A deletion scheduled mid-rotation** changes the answer: for the length of the
  restore window the silo reports the key as scheduled for deletion
  (`dek_deletion_scheduled`) instead.

## 2. At your API boundary

The fallback label is right for a person reading a page and wrong for an API. A
machine cannot tell "Unable to decrypt." from a real note, and it reads HTTP
`200` as success. An API has to signal the failure in a form a machine can
parse: the error's `code`, never the fallback label and never `exc.detail`.

For Django REST Framework, the `[drf]` extra does this. A failed write answers
`{"code", "detail"}` with a status that says whether a retry is worth making,
and a failed read sets the field to `null` and lists its code under
`encryption_suite_errors`. See
[Working with Django REST Framework](working-with-django-rest-framework.md) for
the setup, the status table, uploads and downloads, and what a client of the API
can rely on. Another machine surface, such as a webhook or a GraphQL API, should
follow the same pattern.
