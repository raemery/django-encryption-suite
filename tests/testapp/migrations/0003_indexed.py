# Hand-written for the reason 0002 gives: makemigrations wants to carry an
# unrelated AutoField change on Tenant along with this one.

import django.db.models.deletion
import encryption_suite.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("testapp", "0002_member"),
    ]

    operations = [
        migrations.CreateModel(
            name="Indexed",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "handle",
                    encryption_suite.fields.EncryptedCharField(
                        blank=True, blind_index=True, max_length=150, normalize="casefold", null=True
                    ),
                ),
                # The companion digest column, which the field contributes. Listed
                # because it has to be: see the note in 0002_member.
                ("handle_index", encryption_suite.fields.BlindIndexField(editable=False, max_length=64, null=True)),
                (
                    "team",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="+", to="auth.group"
                    ),
                ),
            ],
        ),
    ]
