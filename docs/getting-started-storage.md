# Getting started with encrypted file uploads

This step-by-step guide walks you through adding `EncryptedFileField` to your project. This page
is the linear quickstart — install, configure, declare a field, upload, and
download. It uses local disk so you can iterate without cloud resources.

This page assumes django-encryption-suite already works for model field encryption
([Getting started](getting-started.md)). Adding encrypted file uploads is
purely additive — your field encryption keeps working unchanged.

The design behind the field, and the pages for storage backends, serving, and
management, are linked from [Encrypted file storage](encrypted-files.md).

## Prerequisites

- A working `ENCRYPTION` block in `settings.py` — `EncryptedFileField`
  reuses your existing silo adapter, KMS adapter, and KEK strategy.
- Silos have been through `setup_encryption_keys` (or will be
  auto-provisioned on first use via `KEY_AUTO_PROVISION = True`). That command
  creates **both** the field keyset and the file keyset for each silo in
  one pass.
- For cloud storage, `django-storages` and the matching SDK installed (e.g.
  `uv add 'django-storages[s3]'`). django-encryption-suite does not pull in
  django-storages itself — storage choice is your project's concern. For local
  disk you need nothing extra.

## 1. Configure the encrypted storage backend

Add an `"encrypted"` alias to Django's `STORAGES`. `EncryptedFileField` reads
this alias and wraps the backend with encryption automatically — no
consumer-side storage class is required:

```python
# settings.py
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {"location": "/var/media/public"},
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
    "encrypted": {
        # Private encrypted uploads — local disk for now.
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {"location": "/var/data/encrypted-files"},
    },
}
```

For local development you can omit the `"encrypted"` alias entirely — the
field falls back to `"default"`, and further to `FileSystemStorage`. When
you're ready for cloud storage, swap the alias backend per
[Storage backends](storage-backends.md); nothing else changes.

## 2. Declare the model fields

```python
from encryption_suite.fields import EncryptedCharField, EncryptedFileField

class Document(models.Model):
    team = models.ForeignKey("teams.Team", on_delete=models.CASCADE)
    file = EncryptedFileField(display_name_field="file_display_name")
    file_display_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

The companion `file_display_name` column is a plain `EncryptedCharField` —
declare it yourself, following the same pattern as Django's `ImageField` +
`width_field`. This keeps the field visible in migrations, `_meta`
introspection, and the admin without hidden machinery. No `storage=` argument
is needed — the field reads from `STORAGES["encrypted"]`.

`display_name_field` is required: without it, the model class fails to load
with a `TypeError`. It must name an `EncryptedCharField` on the same model —
any other field fails [system check `E024`](configuration.md#system-checks),
and a name that matches no field fails `E023`. The column does not need to
appear in your form: on upload, if it is empty, the field fills it with the
original filename (or the result of a
[naming convention](managing-encrypted-files.md#naming-conventions)). A
name longer than the column's `max_length` loses characters from the left,
so the extension is kept. A value already in the column is left alone,
so replacing the file on an existing row keeps the earlier name unless you
clear or set it.

Files land at `encryption_suite/<uuid>.bin` by default. To change that prefix or
enforce a filename scheme, see
[Managing encrypted files](managing-encrypted-files.md#customizing-the-storage-path-prefix).

> **Optional encrypted fields must use `null=True`.** Encrypted fields cannot
> store the empty string, which Django's migrations use as the default for a
> non-nullable `blank=True` column. Always pair `blank=True` with `null=True`
> on optional encrypted fields, including the companion display-name column.

### Companion display-name options

Two product choices are valid:

- Expose `file_display_name` in forms so users can edit file labels.
- Omit it from forms and keep names automatic from the upload filename or a
  `naming_convention` (see [Managing encrypted files](managing-encrypted-files.md#naming-conventions)).

## 3. Generate file encryption keys

File encryption uses a separate keyset from field encryption.
`setup_encryption_keys` creates both in one pass:

```bash
python manage.py setup_encryption_keys
```

## 4. Run migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

## 5. Build the upload form and view

Moving from `FileField` to `EncryptedFileField` keeps the same Django
form/view shape. Upload handling is still `request.FILES` and multipart
forms; what changes is that stored bytes become ciphertext, paths become
opaque, and the user-facing filename moves into the encrypted companion
column.

```python
# forms.py
from django import forms

from .models import Document


class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        # Include file_display_name so users can edit it, or use ["file"]
        # only and let it auto-populate.
        fields = ["file", "file_display_name"]
```

```python
# views.py
from django.shortcuts import redirect, render

from .forms import DocumentForm


def create_document(request):
    form = DocumentForm(request.POST or None, request.FILES or None)
    if form.is_valid():
        form.save()
        return redirect("document_list")
    return render(request, "documents/form.html", {"form": form})
```

```html
<!-- templates/documents/form.html -->
<form method="post" enctype="multipart/form-data">
  {% csrf_token %}
  {{ form.as_p }}
  <button type="submit">Save</button>
</form>
```

A save can fail if the storage backend or KMS is unavailable. Wrap
`form.save()` in `try/except EncryptionError` to surface it cleanly — see
[Handling save / encryption failures](serving-encrypted-files.md#handling-save--encryption-failures).

## 6. Serve downloads through Django

Presigned URLs deliver ciphertext the browser cannot decrypt. Use the bundled
helper instead:

```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from encryption_suite.file_view_helpers import serve_encrypted_file

@login_required
def download_document(request, pk):
    doc = get_object_or_404(Document, pk=pk, team=request.user.team)
    return serve_encrypted_file(request, doc, "file")
```

`serve_encrypted_file` reads the decrypted `file_display_name`, streams the
decrypted bytes, and sets `Content-Disposition: attachment`. The caller is
responsible for authorization and silo context. For inline previews,
the higher-level helpers, and the `kind`/`probe` API, see
[Serving encrypted files](serving-encrypted-files.md).

## Team-scoped uploads (Pegasus teams silo)

When using the Pegasus teams silo, each team has its own encryption
keys, so documents must be scoped to a team for both access control and
encryption context. The model, form, and template are the same as above — only
the ownership field and the views differ. The team silo middleware sets
the encryption context for the request, so encrypt/decrypt is automatic while
the team is active.

```python
# views.py
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from encryption_suite.file_view_helpers import encrypted_file_download_view

from apps.teams.decorators import login_and_team_required

from .forms import DocumentForm
from .models import Document


@login_and_team_required
def create_document(request, team_slug: str):
    form = DocumentForm(request.POST or None, request.FILES or None)
    if form.is_valid():
        instance = form.save(commit=False)
        instance.team = request.team
        instance.save()
        return HttpResponseRedirect(reverse("documents:list", kwargs={"team_slug": team_slug}))
    return render(request, "documents/form.html", {"form": form})


_download = encrypted_file_download_view(
    field_name="file",
    get_instance=lambda request, team_slug, pk: get_object_or_404(
        Document, pk=pk, team=request.team,
    ),
    error_redirect=lambda request, obj: reverse(
        "documents:detail",
        kwargs={"team_slug": request.team.slug, "pk": obj.pk},
    ),
)


@login_and_team_required
def download_document(request, team_slug: str, pk):
    return _download(request, team_slug=team_slug, pk=pk)
```

```python
# urls.py
from django.urls import path

from . import views

team_urlpatterns = [
    path("documents/new/", views.create_document, name="create"),
    path("documents/<int:pk>/download/", views.download_document, name="download"),
]
```

`encrypted_file_download_view` is the optional level-3 view factory — it
handles instance lookup, the `?inline=1` toggle, embedding headers, and
decrypt-failure redirect in one call. You can equally use
`serve_encrypted_file` directly. See
[Serving encrypted files](serving-encrypted-files.md) for all three levels.
