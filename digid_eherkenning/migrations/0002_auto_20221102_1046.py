# Generated by Django 3.2.16 on 2022-11-02 10:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("digid_eherkenning", "0001_initial"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="digidconfiguration",
            options={"verbose_name": "Digid configuration"},
        ),
        migrations.AlterModelOptions(
            name="eherkenningconfiguration",
            options={"verbose_name": "Eherkenning/eIDAS configuration"},
        ),
        migrations.AlterField(
            model_name="digidconfiguration",
            name="base_url",
            field=models.URLField(
                help_text="Base URL of the application, without trailing slash.",
                max_length=100,
                verbose_name="base URL",
            ),
        ),
        migrations.AlterField(
            model_name="eherkenningconfiguration",
            name="base_url",
            field=models.URLField(
                help_text="Base URL of the application, without trailing slash.",
                max_length=100,
                verbose_name="base URL",
            ),
        ),
    ]
