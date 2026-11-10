# Working with django-allauth

This page explains which columns this package can encrypt in a project that uses
django-allauth, and which stay in plaintext.

Neither package depends on the other. `encryption_suite.contrib.allauth` imports
nothing from django-allauth, and django-allauth imports nothing from this
package — the only thing joining them is a dotted path in your settings.

## Plaintext columns

Encrypting your own user model is straightforward: `CustomUser.email` and
`CustomUser.username` are yours, so you redeclare them with
[`key_set="system"`](system-wide-silos.md) and move on.

It achieves less than it appears to. django-allauth keeps the same address in
columns of its own, next to credentials:

| Column | Holds |
|---|---|
| `account.EmailAddress.email` | one row per address, with `verified` and `primary` |
| `socialaccount.SocialApp.secret` and `key` | the credentials of a provider app saved in the database |
| `socialaccount.SocialToken.token` and `token_secret` | the tokens a provider handed back, when `SOCIALACCOUNT_STORE_TOKENS` is on |
| `socialaccount.SocialAccount.extra_data` | whatever a provider returned, commonly including the address |
| `socialaccount.SocialAccount.uid` | the provider's identifier, which for some providers is the address |
| `mfa.Authenticator.data` | the TOTP secret, the recovery-code seed, a WebAuthn credential |

None of these models is swappable, every one of the fields is declared in
django-allauth's own source, and as of October 2026 django-allauth offers no way
to choose their field classes. So this package cannot encrypt them. The one
exception is the pair of MFA secrets below, which django-allauth routes through
hooks a project can override.

The address also reaches the session during an in-flight social signup or
login-by-code, and `django_admin_log`, which records `str(EmailAddress)`.

During a social signup that is not yet finished, django-allauth keeps the
provider's token, unsaved, in the session in plaintext. With a database session
backend, the `django_session` table therefore holds that token unencrypted until
the signup completes or the session expires.

## MFA secrets

django-allauth routes the TOTP secret and the recovery-code seed through
`MFAAdapter.encrypt()` and `decrypt()`, a pair of hooks that return their argument
unchanged unless a project overrides them. `MFASecretEncryptionMixin` is that
override:

```python
from allauth.mfa.adapter import DefaultMFAAdapter
from encryption_suite.contrib.allauth import MFASecretEncryptionMixin


class EncryptedMFAAdapter(MFASecretEncryptionMixin, DefaultMFAAdapter):
    pass


MFA_ADAPTER = "myproject.adapters.EncryptedMFAAdapter"
```

The secrets are encrypted under the [system silo's keys](system-wide-silos.md#keys),
so you need `ENV_KEY_STORES` configured. Rows written before the adapter was set keep reading
as they are.

The hooks see only those two strings, so the rest of `Authenticator.data` — a
WebAuthn credential, the record of which recovery codes are used — stays in
plaintext. They are also handed no row, so a secret is not bound to the
`Authenticator` holding it the way this package's field values are bound to
theirs.

**When a secret cannot be read**, the mixin returns a random secret rather than
raising, because django-allauth has no way to handle a failed decrypt on the login
path. The code the user typed fails to validate, and the log says the cause was a
key. While the keys are unavailable, a user with MFA on cannot sign in, and sees
only that the code was wrong.

## Encrypting your own user model alongside django-allauth

Two of django-allauth's behaviors meet your user model's columns, and both need
attention once those columns are encrypted.

**The admin searches.** `EmailAddressAdmin` and `SocialAccountAdmin` both append
your user fields to their searches with a `user__` prefix, and search them by
substring, which an encrypted column cannot do. Re-register them with exact
matches on those fields:

```python
from allauth.account.admin import EmailAddressAdmin
from allauth.account.models import EmailAddress
from django.contrib import admin

admin.site.unregister(EmailAddress)


@admin.register(EmailAddress)
class EncryptedEmailAddressAdmin(EmailAddressAdmin):
    def get_search_fields(self, request):
        return [f"={name}" if name.startswith("user__") else name for name in super().get_search_fields(request)]
```

`SocialAccountAdmin` takes the same override. Your own user admin needs the same:
`search_fields = ("=email", ...)`.

**Generated usernames.** `generate_unique_username` reads
`USER_MODEL_USERNAME_FIELD` with `values_list`, which returns the column without
going through the field. With an encrypted username the collision check compares
candidates against ciphertext, never matches, and always reports the name free;
the insert then fails on the uniqueness constraint. It matters only when
django-allauth generates usernames and yours is encrypted.

## Related

- [System-wide silos](system-wide-silos.md) — `key_set="system"` and the system silo's keys
- [Configuration reference](configuration.md#env_key_stores) — the env key store and `ENV_KEY_STORES`
