# Internationalization (i18n)

django-encryption-suite supports Django's translation framework for every
string a person can see: exception messages that may be surfaced to end users,
and the admin interface — page and column labels, actions, and model field
`verbose_name` and `help_text`.  Log messages are always in English (see
[Design decisions](#design-decisions) below).

---

## Translatable messages

There are **three**, and every error the package raises carries one of them.
Each is a named constant in `exceptions.py` wrapped with `gettext_lazy`, and no
raise site passes a string literal — a test rejects one even when its text would
otherwise be approved. So this table is the whole user-facing surface, and
translating these three covers it.

| Message (English) | Constant | Raised by |
|---|---|---|
| `Encryption and decryption are unavailable for this data.` | `GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE` | Every reason the keys cannot be used: a bad configuration, a key encryption key that is absent or inside its deletion window, a data key scheduled for deletion or deleted, a KMS call that failed, a provider or backend mismatch, a data key rotation in flight. |
| `Encryption failed.` | `GENERIC_ENCRYPT_FAILED_USER_MESSAGE` | The keys were fine and the write failed: `EncryptedFieldEncryptionError`, `EncryptedFileEncryptionError`, `FieldAlreadyEncryptedError`, and `EncryptedFileStorageError` on a write or an existence check. |
| `Decryption failed.` | `GENERIC_DECRYPT_FAILED_USER_MESSAGE` | The keys were fine and the read failed: `EncryptedFieldDecryptionError`, `EncryptedFileDecryptionError`, and `EncryptedFileStorageError` on a read. |

Three things follow from how few there are, and each is deliberate:

- **The first message names both directions.** Every site that raises it is
  reachable from a read as well as a write, so saying only "encryption" told
  someone opening a record that their save had failed.
- **It is scoped to "this data" rather than being unqualified.** These failures
  are per-silo; an unqualified "unavailable" reads as the whole application
  being down. The qualifier stays vague because the boundary is a team, tenant,
  workspace, or organization depending on your project.
- **No message says why, and none says "currently".** The reason is an
  operator's question, answered by the stable `exc.code` slug and the log — see
  [Error codes](error-codes.md). A message that implied the condition was
  temporary would invite a retry that a missing key or a bad setting never
  satisfies.

A *new* message is therefore expensive: it must be added to every locale
catalog the package ships. Reuse one of these three before inventing a fourth.

UI labels are a separate category. The label `Encrypted file`, which
`EncryptedClearableFileInput` shows for the current file (see
[Forms](managing-encrypted-files.md#forms)), is translated like any other interface
string, but no error carries it and it is not one of the three messages above.

---

## Shipped translations

The package ships compiled catalogs for Arabic (`ar`), German (`de`), English
(`en`), Spanish (`es`), Persian (`fa`), French (`fr`), Italian (`it`), Punjabi
(`pa`), Portuguese (`pt`), Tagalog (`tl`), Cantonese in Traditional script
(`yue_Hant`) and Simplified Chinese (`zh_Hans`). Django loads them from the
installed app's `locale` directory, so a project that activates one of those
languages gets the package's strings translated with no configuration.

## Adding a language or changing a translation

`makemessages` scans your project's own files, not installed packages, so it
does not collect the package's strings. Write the entries into a catalog of
your own instead. Catalogs in `LOCALE_PATHS` take precedence over an app's, so
the same catalog also overrides a shipped translation.

### 1. Point `LOCALE_PATHS` at your catalogs

```python
LOCALE_PATHS = [
    BASE_DIR / "locale",
]
```

### 2. Add the entries

Copy the `msgid` entries you need from the package's
`encryption_suite/locale/en/LC_MESSAGES/django.po` into your catalog for the
target language (e.g. `locale/ja/LC_MESSAGES/django.po`), and translate them:

```po
msgid "Encryption failed."
msgstr "暗号化に失敗しました。"

msgid "Decryption failed."
msgstr "復号に失敗しました。"
```

### 3. Compile message files

```bash
python manage.py compilemessages
```

### 4. Activate the language

Django selects the active language from the request (via
`LocaleMiddleware`) or from `LANGUAGE_CODE` in settings.  No
django-encryption-suite-specific configuration is needed.

---

## Design decisions

### Exception messages

Exception messages raised during `encrypt()` and `decrypt()` operations
flow through the Django ORM field protocol and may reach end users via
error views, DRF exception handlers, or form validation output.
Translating these messages ensures that applications serving non-English
users can present errors in the appropriate language.

### Admin strings and field help text

Everything the admin renders is translatable: the Reconcile Keys page and test
console, changelist column headers and action labels, and each model field's
`verbose_name` **and** `help_text`.  Help text describes a field to whoever is
reading the form, so it belongs with the rest of the interface rather than with
the operator logs — even though several entries describe package internals.

One nuance: no row stores operator detail. A failed deletion records the slug
`failed_at_provider` and nothing else; the provider's own words are in the log,
untruncated and always English, under the raise site's error code. That split is
deliberate — a row is rendered in the reader's language, and a sentence from a
provider cannot be.

### Log messages

All `logger.*()` messages remain in English regardless of the active
locale.  This is intentional:

- **Searchability**: Log aggregation tools (Datadog, Splunk, ELK) rely on
  consistent message strings for grouping, alerting, and dashboards.
  Translated log messages would fragment these across locales.
- **No request context**: Many log entries (cache sweeps, startup
  warnings, auth retries) are not tied to a user request and have no
  meaningful locale.
- **Ops audience**: Logs are consumed by developers and operations staff,
  not end users.  English is the standard for operational logging, even in
  fully localized applications.

This follows the same pattern as Django itself, which logs in English
regardless of `LANGUAGE_CODE`.

### Startup and configuration errors

Errors raised during Django startup (`ImproperlyConfigured`,
`RuntimeError` from settings validation) are seen only in deployment logs,
never by end users.  These remain in English.
