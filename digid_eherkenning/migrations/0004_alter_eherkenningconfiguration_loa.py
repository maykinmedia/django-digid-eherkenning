# Generated by Django 4.2.4 on 2023-08-15 13:47

import digid_eherkenning.choices
from django.db import migrations, models
from ..choices import AssuranceLevels


def set_default_loa(apps, schema_editor):
    EherkenningConfiguration = apps.get_model(
        "digid_eherkenning", "EherkenningConfiguration"
    )
    EherkenningConfiguration.objects.filter(loa="").update(loa=AssuranceLevels.low_plus)


class Migration(migrations.Migration):
    dependencies = [
        ("digid_eherkenning", "0003_digidconfiguration_artifact_resolve_content_type"),
    ]

    operations = [
        migrations.RunPython(set_default_loa),
        migrations.AlterField(
            model_name="eherkenningconfiguration",
            name="loa",
            field=models.CharField(
                choices=[
                    ("urn:etoegang:core:assurance-class:loa1", "Non existent (1)"),
                    ("urn:etoegang:core:assurance-class:loa2", "Low (2)"),
                    ("urn:etoegang:core:assurance-class:loa2plus", "Low (2+)"),
                    ("urn:etoegang:core:assurance-class:loa3", "Substantial (3)"),
                    ("urn:etoegang:core:assurance-class:loa4", "High (4)"),
                ],
                default="urn:etoegang:core:assurance-class:loa3",
                help_text="Level of Assurance (LoA) to use for all the services.",
                max_length=100,
                verbose_name="LoA",
            ),
        ),
        migrations.AddConstraint(
            model_name="eherkenningconfiguration",
            constraint=models.CheckConstraint(
                check=models.Q(("loa__in", digid_eherkenning.choices.AssuranceLevels)),
                name="valid_loa",
            ),
        ),
    ]
