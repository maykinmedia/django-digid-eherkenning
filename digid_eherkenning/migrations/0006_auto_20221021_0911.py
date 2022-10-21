# Generated by Django 3.2.15 on 2022-10-21 09:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("digid_eherkenning", "0005_auto_20221020_2135"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="eherkenningmetadataconfiguration",
            name="eh_service_language",
        ),
        migrations.RemoveField(
            model_name="eherkenningmetadataconfiguration",
            name="eidas_service_language",
        ),
        migrations.RemoveField(
            model_name="eherkenningmetadataconfiguration",
            name="requested_attributes",
        ),
        migrations.AddField(
            model_name="eherkenningmetadataconfiguration",
            name="eh_requested_attributes",
            field=models.JSONField(
                default=list,
                help_text="A list of additional requested attributes. A single requested attribute can be a string (the name of the attribute) or an object with keys 'name' and 'required', where 'name' is a string and 'required' a boolean'.",
                verbose_name="requested attributes",
            ),
        ),
        migrations.AddField(
            model_name="eherkenningmetadataconfiguration",
            name="eidas_requested_attributes",
            field=models.JSONField(
                default=list,
                help_text="A list of additional requested attributes. A single requested attribute can be a string (the name of the attribute) or an object with keys 'name' and 'required', where 'name' is a string and 'required' a boolean'.",
                verbose_name="requested attributes",
            ),
        ),
        migrations.AddField(
            model_name="eherkenningmetadataconfiguration",
            name="service_language",
            field=models.CharField(
                default="nl",
                help_text="Metadata for eHerkenning/eidas will contain this language key",
                max_length=2,
                verbose_name="service language",
            ),
        ),
    ]