"""The test app's whole schema, in one migration.

Nothing has shipped and no database survives a run, so there is no history to
preserve: a new model here belongs in this file, not in a second migration.
"""

import django.db.models.deletion
from django.db import migrations, models

import encryption_suite.fields
import encryption_suite.storage


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("auth", "__first__"),
    ]

    operations = [
        migrations.CreateModel(
            name="Tenant",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=100)),
            ],
            options={"app_label": "testapp"},
        ),
        migrations.CreateModel(
            name="Workspace",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=100)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name="Note",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("author", models.CharField(blank=True, default="", max_length=100)),
                ("title", encryption_suite.fields.EncryptedCharField(blank=True, max_length=200, null=True)),
                ("body", encryption_suite.fields.EncryptedTextField(blank=True, null=True)),
                (
                    "team",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to="auth.group"),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Document",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "upload",
                    encryption_suite.fields.EncryptedFileField(
                        blank=True,
                        display_name_field="upload_name",
                        null=True,
                        storage=encryption_suite.storage.get_encrypted_storage,
                    ),
                ),
                ("upload_name", encryption_suite.fields.EncryptedCharField(blank=True, max_length=255, null=True)),
                (
                    "team",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to="auth.group"),
                ),
            ],
        ),
        migrations.CreateModel(
            name="HiddenNote",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("hidden", models.BooleanField(default=False)),
                ("secret", encryption_suite.fields.EncryptedTextField(blank=True, null=True)),
                (
                    "team",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to="auth.group"),
                ),
            ],
        ),
    ]
