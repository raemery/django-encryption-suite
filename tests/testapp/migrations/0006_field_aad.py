from django.db import migrations

import encryption_suite.fields
import encryption_suite.storage


class Migration(migrations.Migration):
    dependencies = [
        ("testapp", "0005_portrait"),
    ]

    operations = [
        migrations.AlterField(
            model_name="document",
            name="upload",
            field=encryption_suite.fields.EncryptedFileField(
                aad=("team",),
                blank=True,
                display_name_field="upload_name",
                null=True,
                storage=encryption_suite.storage.get_encrypted_storage,
            ),
        ),
        migrations.AlterField(
            model_name="document",
            name="upload_name",
            field=encryption_suite.fields.EncryptedCharField(aad=("team",), blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name="note",
            name="body",
            field=encryption_suite.fields.EncryptedTextField(aad=("team", "author"), blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="note",
            name="title",
            field=encryption_suite.fields.EncryptedCharField(
                aad=("team", "author"), blank=True, max_length=200, null=True
            ),
        ),
    ]
