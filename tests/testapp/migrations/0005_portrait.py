# Hand-written for the reason 0002 gives: makemigrations wants to carry an
# unrelated AutoField change on Tenant along with this one.

from django.db import migrations, models

import encryption_suite.fields
import encryption_suite.storage


class Migration(migrations.Migration):
    dependencies = [
        ("testapp", "0004_indexedshared"),
    ]

    operations = [
        migrations.CreateModel(
            name="Portrait",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "image",
                    encryption_suite.fields.EncryptedFileField(
                        blank=True,
                        display_name_field="image_name",
                        key_set="system",
                        null=True,
                        storage=encryption_suite.storage.get_encrypted_storage,
                    ),
                ),
                (
                    "image_name",
                    encryption_suite.fields.EncryptedCharField(blank=True, key_set="system", max_length=255, null=True),
                ),
            ],
        ),
    ]
