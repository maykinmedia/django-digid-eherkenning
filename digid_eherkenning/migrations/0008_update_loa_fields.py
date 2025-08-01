# Generated by Django 4.2.10 on 2024-03-08 08:45

from django.db import migrations, models

import digid_eherkenning.choices


class Migration(migrations.Migration):
    dependencies = [
        (
            "digid_eherkenning",
            "0007_eherkenningconfiguration_service_description_url",
        ),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="eherkenningconfiguration",
            name="valid_loa",
        ),
        migrations.RenameField(
            model_name="eherkenningconfiguration",
            old_name="loa",
            new_name="eh_loa",
        ),
        migrations.AlterField(
            model_name="eherkenningconfiguration",
            name="eh_loa",
            field=models.CharField(
                choices=[
                    ("urn:etoegang:core:assurance-class:loa1", "Non existent (1)"),
                    ("urn:etoegang:core:assurance-class:loa2", "Low (2)"),
                    ("urn:etoegang:core:assurance-class:loa2plus", "Low (2+)"),
                    ("urn:etoegang:core:assurance-class:loa3", "Substantial (3)"),
                    ("urn:etoegang:core:assurance-class:loa4", "High (4)"),
                ],
                default="urn:etoegang:core:assurance-class:loa3",
                help_text="Level of Assurance (LoA) to use for the eHerkenning service.",
                max_length=100,
                verbose_name="eHerkenning LoA",
            ),
        ),
        migrations.AddField(
            model_name="eherkenningconfiguration",
            name="eidas_loa",
            field=models.CharField(
                choices=[
                    ("urn:etoegang:core:assurance-class:loa1", "Non existent (1)"),
                    ("urn:etoegang:core:assurance-class:loa2", "Low (2)"),
                    ("urn:etoegang:core:assurance-class:loa2plus", "Low (2+)"),
                    ("urn:etoegang:core:assurance-class:loa3", "Substantial (3)"),
                    ("urn:etoegang:core:assurance-class:loa4", "High (4)"),
                ],
                default="urn:etoegang:core:assurance-class:loa3",
                help_text="Level of Assurance (LoA) to use for the eIDAS service.",
                max_length=100,
                verbose_name="eIDAS LoA",
            ),
        ),
        migrations.AddConstraint(
            model_name="eherkenningconfiguration",
            constraint=models.CheckConstraint(
                check=models.Q(
                    models.Q(
                        ("eh_loa__in", digid_eherkenning.choices.AssuranceLevels),
                        ("eidas_loa__in", digid_eherkenning.choices.AssuranceLevels),
                    )
                ),
                name="valid_loa",
            ),
        ),
    ]
