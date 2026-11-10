from django.db import models

from encryption_suite.fields import (
    EncryptedCharField,
    EncryptedDateField,
    EncryptedEmailField,
    EncryptedFileField,
    EncryptedTextField,
)


class Tenant(models.Model):
    """Minimal silo model for tests."""

    name = models.CharField(max_length=100)

    class Meta:
        app_label = "testapp"

    def __str__(self) -> str:
        return self.name


# The rotation tests' data. Each model reaches its silo — an auth Group, which the
# suite's silo adapter names in model_label — through exactly one foreign key, so
# reencrypt_data resolves every one of them by introspection.


class Note(models.Model):
    """Field data bound to its silo and author, so tampering either fails the read."""

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    author = models.CharField(max_length=100, blank=True, default="")
    title = EncryptedCharField(max_length=200, null=True, blank=True, aad=("team", "author"))
    body = EncryptedTextField(null=True, blank=True, aad=("team", "author"))

    class Meta:
        app_label = "testapp"


class Document(models.Model):
    """File data, with its display name as field data beside it."""

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    upload = EncryptedFileField(display_name_field="upload_name", null=True, blank=True, aad=("team",))
    upload_name = EncryptedCharField(max_length=255, null=True, blank=True, aad=("team",))

    class Meta:
        app_label = "testapp"


class LiveWorkspaceManager(models.Manager):
    """An ordinary soft-delete default manager: a deleted workspace stops showing."""

    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=True)


class Workspace(models.Model):
    """A silo model whose default manager hides rows that still own data.

    The silo-side counterpart to :class:`HiddenNote`. A workspace in the trash
    still has every row it ever had, and support restores it on request — so
    enumeration must list it, and the deletion gate must not read it as gone.
    """

    name = models.CharField(max_length=100)
    deleted_at = models.DateTimeField(null=True, blank=True)

    objects = LiveWorkspaceManager()

    class Meta:
        app_label = "testapp"

    def __str__(self) -> str:
        return self.name


class VisibleManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(hidden=False)


class HiddenNote(models.Model):
    """A default manager that hides rows, which a rotation must still convert."""

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    hidden = models.BooleanField(default=False)
    secret = EncryptedTextField(null=True, blank=True)

    objects = VisibleManager()

    class Meta:
        app_label = "testapp"


class Member(models.Model):
    """Columns encrypted under the system silo's keys (``key_set="system"``) rather than a silo's.

    No silo foreign key, deliberately: a member belongs to no silo, which is the
    case ``key_set="system"`` exists for. Lives in a real app with a real migration so
    the migration helpers can be tested against the historical model ``migrate``
    would hand them, rather than against a double that cannot reproduce what they
    get wrong.
    """

    email = EncryptedEmailField(key_set="system", blind_index=True, normalize="casefold", null=True)
    handle = EncryptedCharField(key_set="system", max_length=150, null=True)
    joined = EncryptedDateField(key_set="system", null=True)

    class Meta:
        app_label = "testapp"

    def __str__(self) -> str:
        return str(self.pk)


class Portrait(models.Model):
    """A file under the system silo's file key, in a real app so ``reencrypt_data --silo-kind system`` finds it."""

    image = EncryptedFileField(key_set="system", display_name_field="image_name", null=True, blank=True)
    image_name = EncryptedCharField(key_set="system", max_length=255, null=True, blank=True)

    class Meta:
        app_label = "testapp"


class Indexed(models.Model):
    """Silo data carrying a blind index, in a real app with a real migration.

    A rotation resolves its targets from the app registry and its worklist names
    each model by label, so the transient models the rest of the suite declares —
    whose app is deliberately not installed — cannot be rotated at all. This one
    can.
    """

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    handle = EncryptedCharField(
        max_length=150,
        null=True,
        blank=True,
        blind_index=True,
        normalize="casefold",
    )

    class Meta:
        app_label = "testapp"

    def __str__(self) -> str:
        return str(self.pk)


class IndexedShared(models.Model):
    """The same, keeping its digests in the package's own table.

    Where a digest is absent *from* differs between the two storage strategies,
    and a program that looks for a missing one has to know both — so the
    installed app carries one model of each rather than leaving the shared-table
    strategy to transient models nothing can enumerate.
    """

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    handle = EncryptedCharField(
        max_length=150,
        null=True,
        blank=True,
        blind_index=True,
        normalize="casefold",
        blind_index_storage="table",
    )

    class Meta:
        app_label = "testapp"

    def __str__(self) -> str:
        return str(self.pk)
