"""Form widgets for encrypted model fields.

:class:`EncryptedClearableFileInput` is the default widget for
:class:`~encryption_suite.fields.EncryptedFileField`. Django's stock
``ClearableFileInput`` renders the current file as a link whose text is the
storage name and whose target is ``storage.url()``. For an encrypted file
the name is the opaque storage path and the URL serves ciphertext, so this
widget shows a fixed label instead and renders no link.
"""

from __future__ import annotations

from django.forms.widgets import ClearableFileInput
from django.utils.translation import gettext_lazy as _


class EncryptedClearableFileInput(ClearableFileInput):
    """``ClearableFileInput`` that names the current file without linking to it.

    ``encrypted_text`` replaces the storage-name link. Override it on a
    subclass or pass ``encrypted_text=`` to the constructor. The Clear checkbox
    and the change input behave exactly as they do on the stock widget.
    """

    encrypted_text = _("Encrypted file")
    template_name = "encryption_suite/widgets/encrypted_clearable_file_input.html"

    def __init__(self, attrs=None, encrypted_text=None):
        super().__init__(attrs)
        if encrypted_text is not None:
            self.encrypted_text = encrypted_text

    def is_initial(self, value) -> bool:
        # The stock check reads ``value.url``, which calls ``storage.url()``
        # and raises on storage with no public URL. The link is gone, so a
        # stored name is all that matters.
        return bool(value)

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        context["widget"]["encrypted_text"] = self.encrypted_text
        return context
