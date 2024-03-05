# Generated by Django 4.2.10 on 2024-03-04 13:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("digid_eherkenning", "0006_digidconfiguration_metadata_file_source_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="eherkenningconfiguration",
            name="service_description_url",
            field=models.URLField(
                default="",
                help_text="The URL where the service description can be found.",
                max_length=255,
                verbose_name="service description URL",
            ),
        ),
    ]