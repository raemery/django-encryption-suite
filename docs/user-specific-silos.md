# User-specific silos

A user-specific silo gives each user their own data keys. Data encrypted under one
user's keys cannot be read while another user is acting, a staff member in the admin
panel included.

There is no special user key set. A key set is one silo adapter bound to one key
store, so you declare an ordinary key set, bind it to one of the user silo adapters, and
name it in a field's `key_set`. Any name of at most 32 lowercase characters works. A user
is a silo with up to three data keys of their own in each key set that uses the adapter:
a field key, a file key and a blind index key.

## The user silo adapters

Both adapters make each user a silo and read the acting user, as the team adapter reads
the acting team. They differ only in a write that happens while nobody is acting:

| Adapter | Label and uid | A read | A write while a user is acting | A write while nobody is acting |
|---|---|---|---|---|
| `ActingUserSiloAdapter` | `user`, `user-<pk>` | Under the acting user's keys | Under the acting user's keys | Fails |
| `ActingUserOrOwnerSiloAdapter` | `user_owner`, `user_owner-<pk>` | Under the acting user's keys | Under the acting user's keys | Under the keys of the user the row belongs to |

With nobody acting, a read fails under either adapter, the way a team silo with no team
fails. For a read, and for a write while a user is acting, the user comes from the
request, never from the row. Only a write with nobody acting under
`ActingUserOrOwnerSiloAdapter` asks the row who owns it. See
[Who chooses the silo](#who-chooses-the-silo).

This page calls the key sets `user` and `user_owner`, after the adapters' labels.

## When to choose user-specific silos

User-specific silos do not suit every deployment. Choose them only when a user's data
must be unreadable while someone else is acting. These costs come with them:

- **A key per user.** Each user has up to three data keys, and with a per-user key
  encryption key the KMS holds one more key for each user. Provisioning, rotation,
  shredding and reconcile all scale with the number of users. A bare
  `setup_encryption_keys` provisions every user, so run it with `--dry-run` first on a
  large deployment.
- **Enumeration.** The Reconcile Keys page, reconcile and setup list every user. A very
  large user table makes them slow and memory-heavy.
- **No lookups across users.** Each user's blind index key differs, so an exact lookup
  finds rows of the acting user only.
- **An acting user on every read.** Code that runs with no request needs to say who is
  acting (see [The acting user](#the-acting-user)). Under `ActingUserSiloAdapter` that
  holds for every write too.

If these costs are too high, an alternative is to bind each value to its user with
associated data. Keep the model in an ordinary team key set, give it a `user` foreign
key, and list that column in each encrypted field's `aad=`. Every value is then tied to
the user its row names, so a value copied onto another user's row fails to decrypt.

The downside is weaker protection against other users reading the value. The associated
data comes from the row, not from who is acting, so any code running in the team's
context reads every member's values, and only your views and admin classes keep one user
from another's rows. Nor can you shred one user's values: they share the team's keys.
See [Row-identity binding](security.md#row-identity-binding-optional).

## Choosing an adapter

Choose `ActingUserSiloAdapter` when your own code makes every write, and can say who is
acting when it does. A write with nobody acting is then a bug, and the adapter fails it.

Choose `ActingUserOrOwnerSiloAdapter` when code you cannot change writes a user's row
before anyone is acting. django-allauth, for example, saves a returning user's social
account while the sign-in request is still anonymous.

## Protection

The key for a read is chosen by who is acting, and the application holds the key
encryption key. A staff member who opens another user's row in the admin panel sees the
fallback label or a ciphertext preview, never that user's data. Someone with a shell, the
database and the key encryption key can still decrypt, and an impersonation tool acts as
the user it impersonates. That is the limit of keys the server holds.

## Declaring the key set

```python
ENCRYPTION = {
    "KEY_SETS": {
        "default": {"silo": "yourapp.encryption.TeamSiloAdapter", "key_store": "kms_teams"},
        "user": {"silo": "encryption_suite.adapters.silos.user.ActingUserSiloAdapter", "key_store": "kms_users"},
        "system": {"key_store": "login"},
    },
    "KMS_KEY_STORES": {
        "kms_teams": {...},
        "kms_users": {...},
    },
    "SILO_AUTO_KEY_CREATION": ["default", "user"],
    "SILO_AUTO_KEY_DELETION": ["default", "user"],
    "DEK_CACHE_MAX": {"user": 10_000},
}
```

For `ActingUserOrOwnerSiloAdapter`, declare a `user_owner` key set the same way, with
`encryption_suite.adapters.silos.user.ActingUserOrOwnerSiloAdapter` as its `silo`.

Then name the key set in the field:

```python
from django.conf import settings
from django.db import models
from encryption_suite.fields import EncryptedTextField


class Note(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    body = EncryptedTextField(key_set="user")
```

The adapters' silo is the model named by `AUTH_USER_MODEL`. Their description of a user
is the primary key, never the username or the email, because the description appears on
admin pages and in logs.

The key store decides how strong a shred is. Each choice below names what shredding a
user deletes:

| Key store | A user's shred deletes |
|---|---|
| Per-silo KMS store with a user `KEK_TEMPLATE` | The user's key encryption key. A restored backup cannot bring the data back. |
| Shared key encryption key | The user's data key rows. A restored backup brings them back. |
| Env store | The user's data key rows. A restored backup brings them back. |

A per-silo store needs its own `KEK_TEMPLATE`, because two adapters cannot share one
per-silo store and the templates of different stores must not be prefixes of each
other. Each user key set therefore gets a store block of its own, and so do `user` and
`user_owner` when a project declares both. See
[`KMS_KEY_STORES`](configuration.md#kms_key_stores). `DEK_CACHE_MAX` has no default for
a key set you name, so set a limit for each user key set when the user count is large.

## The acting user

`UserContextMiddleware` sets the acting user for a request. Add it to `MIDDLEWARE` below
Django's `AuthenticationMiddleware`:

```python
MIDDLEWARE = [
    ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "encryption_suite.user_context.UserContextMiddleware",
]
```

When a key set is bound to either user silo adapter, the middleware sets the user for
every request. Listing the key set does not turn on user recording for the key lifecycle
ledger: that stays governed by `USER_IDENTITY['SCOPE']`. `manage.py check` reports
`encryption_suite.W060` when the middleware is missing or listed above
`AuthenticationMiddleware`.

Work that runs with no request sets the user itself:

```python
from encryption_suite.user_context import override_current_user

with override_current_user(user.pk):
    note = Note.objects.create(owner=user, body="Only this user reads this.")
```

Use this in Celery tasks and management commands. An API that authenticates inside the
view, such as Django REST Framework token authentication, authenticates after the
middleware has run and seen an anonymous user. Call `set_current_user(user.pk)` from your
authentication class once the user is known.

Callers that have no acting user, such as rotation, shredding and signals, pass the silo
explicitly with `SiloRef("user", f"user-{pk}")`.

## Who chooses the silo

Under `ActingUserOrOwnerSiloAdapter`, a write while nobody is acting goes to the silo of
the user the row belongs to. On the user model that is the row itself. On any other model
it is the user named by the row's one foreign key to `AUTH_USER_MODEL`. An acting user
always wins: a staff member who saves another user's row with someone acting writes it
under the staff member's own keys, as under `ActingUserSiloAdapter`.
`EncryptionAdminMixin` takes encrypted fields off the admin form, so the admin panel does
not write them.

The value and its blind index digest are written under the same silo, so the owner finds
the row with an exact lookup once signed in.

**Server code must set the owner.** The fallback applies exactly when nobody is acting,
and that includes every anonymous endpoint. If such an endpoint lets request input
choose the owner foreign key, a caller can write a value into another user's silo, and
that user then reads it as their own. Set the foreign key from server-side state, never
from a form field or a request parameter.

**Writes that would fail succeed.** A write that `ActingUserSiloAdapter` refuses for
lack of an acting user, such as one from a shell session, a task or a signal, goes to
the owner's silo under `ActingUserOrOwnerSiloAdapter`. Reads from the same code still
fail, so a task cannot read back what it wrote without setting the acting user.

The fallback has these limits. A write in each case needs an acting user, as under
`ActingUserSiloAdapter`:

- **Files.** An `EncryptedFileField` encrypts in the storage layer, which has no row.
- **`QuerySet.update()`.** It writes without the row, and refuses a plaintext value to an
  encrypted column in any case.
- **A row with no owner.** A foreign key left unset, and a new row of the user model
  whose primary key the database assigns on insert, name no owner yet.
- **A model with no owner column.** `manage.py check` reports
  `encryption_suite.W061` for a model on the key set that is not the user model and has
  no foreign key, or more than one, to `AUTH_USER_MODEL`.

## Keys

`SILO_AUTO_KEY_CREATION` makes a new user's field key when the user is saved, on an env
store as on a KMS store. File and blind index keys are made on first use, where
`KEY_AUTO_PROVISION` is on. To give existing users keys, run:

```bash
python manage.py setup_encryption_keys --key-set user
```

`SILO_AUTO_KEY_DELETION` schedules a deleted user's keys for deletion. See
[Destroying keys](management-commands.md#destroying-keys).

After a shred, and once the deletion window has passed, the user's next write makes a
fresh key where `KEY_AUTO_PROVISION` is on. While the window runs, writes are blocked.
Values encrypted under the shredded key stay unreadable.

## Finding a user's rows

`reencrypt_data` finds the rows of a user by the one foreign key from the model to
`AUTH_USER_MODEL`. A model with two such keys, or a path through another model, is
reported by `manage.py check` as `encryption_suite.W053` and needs an adapter subclass
that sets `supports_silo_data_lookup` and implements `queryset_for_silo()`. See
[Finding a silo's rows](silo-adapters.md#finding-a-silos-rows).

## Files

A file field with `key_set="user"` stores its files under `encryption_suite_user/`. The
field encrypts a file under the acting user's file key on write, and decrypts it through
the field on read. To open a file by name, use a storage class that sets
`key_set = "user"`; see [Opening a file by name](managing-encrypted-files.md#opening-a-file-by-name).

## The admin panel

Apply `EncryptionAdminMixin` to the admin class of a model with user-specific columns.
The mixin shows ciphertext previews and takes encrypted fields off the form. Without
it, a column of a user key set decrypts on the staff member's own row and shows the
fallback label on every other user's row. See
[Rendering models with encrypted fields in the admin](admin-panel.md#rendering-models-with-encrypted-fields-in-the-admin).

## Failed reads

A read that fails returns the fallback label, and `{}` for an `EncryptedJSONField`, in
the default lenient mode. Detect a failed read by type with `is_undecryptable()`, as
[Handling errors](handling-errors.md) describes.

## Related

- [Silo adapters](silo-adapters.md#actingusersiloadapter)
- [System-wide silos](system-wide-silos.md)
- [Key rotation](key-rotation.md)
