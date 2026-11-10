"""
Pluggable data-plane crypto backends.

A crypto backend owns the *local* encryption of field values and file
streams — generating a data encryption key (DEK), serializing it to bytes for
the KMS layer to wrap, and turning those bytes back into AEAD / streaming-AEAD
primitives. It is independent of the KMS/KEK layer, which only ever sees the
opaque serialized DEK bytes (see :mod:`encryption_suite.adapters.key_stores.base`).

The backend that makes new keys is selected via ``ENCRYPTION["CRYPTO_BACKEND"]``
and configured with ``ENCRYPTION["CRYPTO_BACKEND_OPTIONS"]``. Two backends ship:
one built on the pyca-cryptography library (the ``cryptography`` package), which
is the default, and one that wraps Google Tink (opt-in via the ``[tink]`` extra).
Both expose the same
:class:`~encryption_suite.adapters.crypto_backends.base.AbstractCryptoEngine`
interface. An existing key is loaded through the backend its row records, so a
change of ``CRYPTO_BACKEND`` leaves existing keys readable until
``reencrypt_data`` moves each silo onto the new one.
"""
