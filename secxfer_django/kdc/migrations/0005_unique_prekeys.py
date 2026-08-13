from django.db import migrations, models


def deduplicate_prekeys(apps, schema_editor):
    PreKey = apps.get_model("kdc", "PreKey")
    duplicates = (
        PreKey.objects.values("user_id", "prekey_id")
        .annotate(count=models.Count("id"))
        .filter(count__gt=1)
    )
    for duplicate in duplicates:
        rows = PreKey.objects.filter(
            user_id=duplicate["user_id"], prekey_id=duplicate["prekey_id"]
        ).order_by("-used", "id")
        keep = rows.first()
        rows.exclude(id=keep.id).delete()


class Migration(migrations.Migration):
    dependencies = [("kdc", "0004_hybrid_identity_and_audit_head")]

    operations = [
        migrations.RunPython(deduplicate_prekeys, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="prekey",
            constraint=models.UniqueConstraint(fields=("user", "prekey_id"), name="unique_prekey_per_user"),
        ),
    ]
