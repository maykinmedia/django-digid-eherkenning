# Generated by Django 4.2.13 on 2024-07-19 12:34

from django.db import migrations

from ..choices import ConfigTypes


def move_certificates(apps, _):
    DigidConfiguration = apps.get_model("digid_eherkenning", "DigidConfiguration")
    EherkenningConfiguration = apps.get_model(
        "digid_eherkenning", "EherkenningConfiguration"
    )
    ConfigCertificate = apps.get_model("digid_eherkenning", "ConfigCertificate")

    for model in (DigidConfiguration, EherkenningConfiguration):
        config = model.objects.first()
        if config is None or not (cert := config.certificate):
            continue
        ConfigCertificate.objects.get_or_create(
            certificate=cert,
            config_type=ConfigTypes(
                f"{config._meta.app_label}.{config._meta.object_name}"
            ),
        )


class Migration(migrations.Migration):

    dependencies = [
        (
            "digid_eherkenning",
            "0011_configcertificate_configcertificate_uniq_config_cert",
        ),
    ]

    operations = [
        # reverse migration is ambiguous, if needed, you can easily use the UI
        migrations.RunPython(move_certificates, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name="digidconfiguration",
            name="certificate",
        ),
        migrations.RemoveField(
            model_name="eherkenningconfiguration",
            name="certificate",
        ),
    ]