# Generated by Django 4.2.13 on 2024-12-18 14:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("digid_eherkenning", "0012_move_config_certificate"),
    ]

    operations = [
        migrations.AlterField(
            model_name="eherkenningconfiguration",
            name="eh_requested_attributes",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="A list of additional requested attributes. A single requested attribute can be a string (the name of the attribute) or an object with keys 'name' and 'required', where 'name' is a string and 'required' a boolean'.",
                verbose_name="requested attributes",
            ),
        ),
        migrations.AlterField(
            model_name="eherkenningconfiguration",
            name="eidas_requested_attributes",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="A list of additional requested attributes. A single requested attribute can be a string (the name of the attribute) or an object with keys 'name' and 'required', where 'name' is a string and 'required' a boolean'.",
                verbose_name="requested attributes",
            ),
        ),
    ]
