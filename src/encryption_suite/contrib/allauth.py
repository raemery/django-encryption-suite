"""An MFA adapter mixin for the secrets django-allauth routes through its adapter.

allauth routes the TOTP secret and the recovery-code seed through
``MFAAdapter.encrypt()`` and ``decrypt()`` — a pair of hooks that return their
argument unchanged unless a project overrides them.
:class:`MFASecretEncryptionMixin` is that override. The project combines it with
allauth's own adapter::

    class EncryptedMFAAdapter(MFASecretEncryptionMixin, DefaultMFAAdapter):
        pass

    MFA_ADAPTER = "myproject.adapters.EncryptedMFAAdapter"

It is a mixin rather than a finished adapter because nothing here imports
allauth, so the project supplies the base class — and needs no extra.

The rest of what allauth stores — ``EmailAddress.email``, social tokens, provider
app secrets, ``SocialAccount.extra_data``, WebAuthn credentials — stays in
plaintext: those columns belong to allauth's models, and allauth gives a project
no way to choose their field classes. See ``docs/working-with-django-allauth.md``.
"""

from __future__ import annotations

import base64
import secrets

from .._logging import get_logger
from ..exceptions import EncryptionError

logger = get_logger(__name__)

#: Label carried on the log line and on ``exc.detail`` for an MFA secret. The
#: column is the JSON that holds the secret, not the secret itself, so there is
#: no field name to name. Written in the form the package's own fields use —
#: ``<app label>.<model>.<attname>`` — so one ``field="…"`` filter reaches these
#: lines and the field lines together.
MFA_FIELD_LABEL = "mfa.Authenticator.data"


class MFASecretEncryptionMixin:
    """Encrypt the MFA secrets allauth routes through its adapter hooks.

    Mixed in ahead of allauth's own adapter, this encrypts the TOTP secret and
    the recovery-code seed under the system silo's field key, because these rows
    belong to allauth rather than to any one silo.

    Both secrets live inside ``Authenticator.data``, but the rest of that JSON —
    a WebAuthn credential, the recovery-code usage state — stays in plaintext.
    ``encrypt()`` and ``decrypt()`` are handed a string with no row and no
    instance. Two things follow from that:

    * **No associated data.** Every other value this package writes is bound to
      the row holding it, so a ciphertext moved to another row stops reading.
      These two cannot be: the hook never learns which row it is working on. A
      secret moved from one ``Authenticator`` to another still decrypts.
    * **A read cannot report failure.** allauth annotates ``decrypt()`` as
      returning ``str``, catches nothing around the call, and has no notion of a
      secret it could not read. Raising would surface a traceback on the login
      path; returning the stored value would reach
      ``base64.b32decode`` and raise there instead.

    So a failed decrypt returns a fresh random secret of the right shape. The
    code the user typed then fails to validate, which is the truthful outcome —
    it did not authenticate — and the log is what says the cause was a key
    rather than a wrong code: the engine has already logged the error, and
    this adds a warning naming the consequence. The value is random per call rather than a
    constant: a fixed placeholder would be a known secret, and anyone able to
    provoke a decrypt failure could compute codes from it.

    Accept the consequence deliberately: while the keys are unavailable, a user
    with MFA on cannot sign in, and sees only that the code was wrong. Both
    outcomes lock the account; only the log tells them apart.
    """

    #: Overridable, for a project that wants these secrets under a label of its
    #: own in the logs.
    mfa_field_label: str = MFA_FIELD_LABEL

    def encrypt(self, text: str) -> str:
        """Return the stored form of *text*.

        Refused for a value that already carries a marker: the engine raises
        :class:`~encryption_suite.exceptions.FieldAlreadyEncryptedError` rather
        than nest one ciphertext inside another, which is what a second run over
        already-converted rows would otherwise do silently.
        """
        from ..engine import SYSTEM_SILO
        from ..registry import get_engine

        return get_engine().encrypt(text, silo=SYSTEM_SILO, field_name=self.mfa_field_label)

    def decrypt(self, encrypted_text: str) -> str:
        """Return the plaintext of *encrypted_text*, or a secret that fails.

        A value without the ciphertext marker is returned unchanged, so rows
        written before this adapter was configured keep working and can be
        converted when the project gets to it.
        """
        from ..engine import SYSTEM_SILO, is_silo_value
        from ..registry import get_engine

        if not is_silo_value(encrypted_text):
            return encrypted_text
        try:
            return get_engine().decrypt(encrypted_text, silo=SYSTEM_SILO, field_name=self.mfa_field_label)
        except EncryptionError:
            # One line, and only the part the preceding line cannot carry. Every
            # error reachable from here is logged at ERROR by the engine before
            # it is raised, with the code and the operator detail on it,
            # so repeating those would double every failure in the log. No
            # ``error_code`` either: nothing is raised from this site, and the
            # slug would otherwise vary with the cause. ``field`` is on both
            # lines, which is what joins them.
            logger.warning(
                "An MFA secret could not be read, so this authentication attempt "
                "fails whatever code was entered; the error line above carries the "
                'cause. field="%s"',
                self.mfa_field_label,
            )
            return _unusable_secret()


def _unusable_secret() -> str:
    """Return a random secret that is well formed for every consumer.

    Base32 satisfies both: the TOTP secret is passed to ``base64.b32decode``,
    and the recovery-code seed is used as an HMAC key through
    ``seed.encode("ascii")``. Twenty bytes encode to 32 characters, a length
    ``b32decode`` accepts without padding complaints.
    """
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


__all__ = [
    "MFA_FIELD_LABEL",
    "MFASecretEncryptionMixin",
]
