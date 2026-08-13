from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("kdc", "0003_add_prekey_reserved_at")]

    operations = [
        migrations.AlterField(
            model_name="useridentity",
            name="identity_pubkey",
            field=models.CharField(max_length=2496),
        ),
        migrations.CreateModel(
            name="AuditChainHead",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("current_hash", models.CharField(default="GENESIS_HASH", max_length=64)),
            ],
        ),
    ]
