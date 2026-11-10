"""Form helpers for models with encrypted fields.

:class:`EncryptionModelForm` is a ``ModelForm`` subclass that handles
the corner case where a row's ciphertext can't be decrypted. Without
intervention, two things go wrong:

* ``ModelForm.__init__`` calls ``model_to_dict(instance, ...)``, which
  invokes our lazy-decrypt descriptor on every form field. On an
  undecryptable row the descriptor returns an
  :class:`UndecryptableValue` sentinel, and the form widget renders
  the sentinel's stringified fallback as the field's apparent current
  value.

* If the user submits the form, that string round-trips through
  ``cleaned_data`` and ``construct_instance`` calls
  ``setattr(instance, name, "Unable to decrypt.")``. The model field's
  ``pre_save`` then encrypts the message itself and writes it back,
  destroying the only copy of the original ciphertext.

This form fixes both problems while keeping the form's behavior as
close to a normal Django form as possible. A healthy row is
indistinguishable from the unencrypted equivalent: every field renders
its current value, every field validates, the form saves. A broken
row's affected fields render empty, are marked read-only, and surface
the failure through Django's standard ``help_text`` channel — without
blocking the form's validity, so the user can still save edits to the
row's other fields.

The form deliberately does not touch widgets, CSS classes, or
``form._errors``. ``help_text`` is the chosen channel because it is
part of the Django field model, presentation-neutral (DRF surfaces it
in OpenAPI schemas, every Django template renders it inline), and does
not affect ``is_valid()``. The file widget, ``EncryptedClearableFileInput``,
is supplied by ``EncryptedFileField.formfield()``, not by this form.

Two policies are supported:

* **Default — protect**
  (``encryption_suite_overwrite_undecryptable = False``). For each
  undecryptable field: blank the initial; mark the form field with
  ``encryption_suite_undecryptable = True``; set ``disabled = True`` and
  ``required = False``; replace ``help_text`` with the field's
  fallback label so the user sees the failure inline; pop the field
  from ``cleaned_data`` on ``_post_clean`` so ``save()`` cannot touch
  the column.

* **Overwrite** (``encryption_suite_overwrite_undecryptable = True``).
  Field stays editable; ``initial`` is blanked so the sentinel string
  is not rendered as the apparent current value; the marker is still
  attached. ``help_text`` is left alone — the user is supplying fresh
  plaintext on purpose, and the surrounding view is responsible for
  any recovery prompting.

Discoverability:

* :attr:`EncryptionModelForm.encryption_suite_undecryptable_fields` —
  list of bound field names that failed to decrypt.

* :attr:`EncryptionModelForm.encryption_suite_undecryptable_errors` —
  mapping of field name to the underlying typed exception.

* ``form.fields[name].encryption_suite_undecryptable`` — per-field marker
  for templates / serializers that want fine-grained branching.

Forms whose ``Meta.fields`` excludes encrypted fields are unaffected;
``model_to_dict`` never invokes the descriptor for fields the form
does not render.
"""

from __future__ import annotations

from django import forms

from .fields import DEFAULT_FALLBACK_LABEL


class EncryptionModelForm(forms.ModelForm):
    """``ModelForm`` that handles undecryptable rows safely.

    The default policy disables affected fields, replaces their
    ``help_text`` with the field's fallback label, and prevents save
    from overwriting ciphertext — without affecting ``is_valid()``, so
    edits to the row's other fields still go through. Set
    ``encryption_suite_overwrite_undecryptable = True`` to opt into a
    recovery flow where the user types a fresh plaintext that replaces
    the broken ciphertext on save.
    """

    encryption_suite_overwrite_undecryptable: bool = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._encryption_suite_apply_field_policy()

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    def _encryption_suite_apply_field_policy(self) -> None:
        """Adjust ``self.fields`` based on the bound instance's decrypt state.

        Reads ``instance.encryption_suite_errors`` — populated as a side
        effect of the descriptor calls performed by ``model_to_dict``
        during ``ModelForm.__init__`` — and either disables each
        affected field (default policy) or simply blanks its initial
        (overwrite policy). In both modes a structured marker
        (``encryption_suite_undecryptable = True``) is attached so other
        rendering layers can detect the failure on a per-field basis.
        """
        instance = getattr(self, "instance", None)
        if instance is None or instance.pk is None:
            return
        errors = getattr(instance, "encryption_suite_errors", None) or {}
        if not errors:
            return

        for name in errors:
            if name not in self.fields:
                continue
            field = self.fields[name]
            # The sentinel stringifies to the fallback label. Rendering
            # it as the field's current value would mislead the user —
            # and on an editable submit, the message itself would
            # round-trip back as plaintext. Blank it.
            self.initial[name] = ""
            # Structured, presentation-neutral marker. Templates / DRF
            # serializers / custom renderers can detect failure
            # per-field without consulting the form-level dict.
            field.encryption_suite_undecryptable = True
            if not self.encryption_suite_overwrite_undecryptable:
                # ``disabled`` makes the widget read-only and tells
                # Django to take the field's value from ``initial``
                # instead of the bound POST data; ``_post_clean`` then
                # pops it from ``cleaned_data`` so the model-form save
                # path never touches the column. ``required = False``
                # keeps validation passing on the empty initial value.
                field.disabled = True
                field.required = False
                # ``help_text`` is the protocol-neutral channel for
                # surfacing the failure: standard Django form
                # rendering shows it inline beneath the field, DRF
                # surfaces it in OpenAPI schemas, and any custom
                # renderer can read it directly. Replacing whatever
                # ``help_text`` the developer declared on the model
                # field is a deliberate divergence — but only on a
                # row that has actually failed to decrypt, only on the
                # form layer, and only under the default policy.
                field.help_text = self._encryption_suite_field_message(name)

    def _post_clean(self):
        """Pop undecryptable fields before ModelForm builds the instance.

        ``ModelForm._post_clean`` calls ``construct_instance``, which
        iterates the model's fields and writes ``cleaned_data[name]``
        onto the instance for every name it finds. Popping before
        super runs means the broken-ciphertext column is never
        touched; the model field's ``pre_save`` then preserves the
        existing ciphertext via a raw-cursor fetch.
        """
        if not self.encryption_suite_overwrite_undecryptable:
            if not hasattr(self, "cleaned_data"):
                self.cleaned_data = {}
            for name in self.encryption_suite_undecryptable_fields:
                self.cleaned_data.pop(name, None)
        super()._post_clean()

    def _get_validation_exclusions(self):
        """Exclude undecryptable fields from instance-level model validation.

        After ``construct_instance``, ``ModelForm._post_clean`` calls
        ``self.instance.full_clean(exclude=self._get_validation_exclusions())``.
        ``Model.clean_fields`` then iterates the model's fields and,
        for each one not in the exclusion set, runs
        ``setattr(instance, name, field.clean(getattr(instance, name)))``.

        On an undecryptable row the ``getattr`` returns the
        :class:`UndecryptableValue` sentinel sitting in
        ``instance.__dict__``. ``Field.to_python`` coerces the sentinel
        to its stringified fallback, ``setattr`` writes the string
        back through the descriptor, and the model field's
        ``pre_save`` then encrypts that string over the original
        ciphertext.

        Django's default exclusion logic only skips empty optional
        fields when the underlying model field has ``blank=False`` —
        ``blank=True`` fields stay in for unique-check purposes. We
        do not need that protection here (under the protect policy we
        are not editing the column at all), and we do need the
        sentinel to survive untouched into ``pre_save``. Adding the
        names to the exclusion set is the cleanest way to make
        ``clean_fields`` leave them alone regardless of the model
        field's ``blank`` setting.

        Skipped under the overwrite policy because the user is
        intentionally supplying fresh plaintext, which must validate.
        """
        exclude = super()._get_validation_exclusions()
        if not self.encryption_suite_overwrite_undecryptable:
            for name in self.encryption_suite_undecryptable_fields:
                exclude.add(name)
        return exclude

    def _encryption_suite_field_message(self, name: str):
        """Resolve the per-field fallback label.

        Per-field ``fallback_label=`` kwarg on the model field
        overrides the package default. Returned as a ``gettext_lazy``
        proxy when the underlying value is one, so the message follows
        the active Django locale at render time.
        """
        try:
            model_field = self._meta.model._meta.get_field(name)
        except Exception:
            return DEFAULT_FALLBACK_LABEL
        custom = getattr(model_field, "_fallback_label", None)
        return custom if custom is not None else DEFAULT_FALLBACK_LABEL

    # ------------------------------------------------------------------
    # Discoverability
    # ------------------------------------------------------------------

    @property
    def encryption_suite_undecryptable_fields(self) -> list[str]:
        """Names of bound encrypted fields that failed to decrypt."""
        instance = getattr(self, "instance", None)
        if instance is None:
            return []
        errors = getattr(instance, "encryption_suite_errors", None) or {}
        return list(errors.keys())

    @property
    def encryption_suite_undecryptable_errors(self) -> dict[str, Exception]:
        """Mapping of field name to the underlying decryption exception."""
        instance = getattr(self, "instance", None)
        if instance is None:
            return {}
        return dict(getattr(instance, "encryption_suite_errors", None) or {})


__all__ = ["EncryptionModelForm"]
