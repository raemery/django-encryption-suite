# Hand-written: makemigrations wanted to carry an unrelated AutoField change on
# Tenant along with this, left for whoever cares to make that change on purpose.

from django.db import migrations, models

import encryption_suite.fields


class Migration(migrations.Migration):
    dependencies = [
        ("testapp", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Member",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "email",
                    encryption_suite.fields.EncryptedEmailField(
                        blind_index=True, key_set="system", max_length=254, normalize="casefold", null=True
                    ),
                ),
                ("handle", encryption_suite.fields.EncryptedCharField(key_set="system", max_length=150, null=True)),
                ("joined", encryption_suite.fields.EncryptedDateField(key_set="system", null=True)),
                # email's companion digest column, which the field contributes.
                # Listed here because it has to be: rendering this state builds
                # the field and the field adds the column, so a file that left it
                # out would disagree with the model makemigrations compares
                # against, and the AddField it kept proposing would collide with
                # the column this CreateModel already made.
                ("email_index", encryption_suite.fields.BlindIndexField(editable=False, max_length=64, null=True)),
            ],
        ),
    ]
