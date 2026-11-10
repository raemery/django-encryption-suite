# Hand-written for the reason 0002 gives: makemigrations wants to carry an
# unrelated AutoField change on Tenant along with this one.

import django.db.models.deletion
from django.db import migrations, models

import encryption_suite.fields


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("testapp", "0003_indexed"),
    ]

    operations = [
        migrations.CreateModel(
            name="IndexedShared",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "handle",
                    encryption_suite.fields.EncryptedCharField(
                        blank=True,
                        blind_index=True,
                        blind_index_storage="table",
                        max_length=150,
                        normalize="casefold",
                        null=True,
                    ),
                ),
                # No companion column here: this field's digests are rows of the
                # package's own table, which its own migrations create.
                (
                    "team",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to="auth.group"),
                ),
            ],
        ),
    ]
