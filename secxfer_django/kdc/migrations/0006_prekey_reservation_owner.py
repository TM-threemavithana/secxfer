from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("kdc", "0005_unique_prekeys")]

    operations = [
        migrations.AddField(
            model_name="prekey",
            name="reserved_by_key_id",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
    ]
