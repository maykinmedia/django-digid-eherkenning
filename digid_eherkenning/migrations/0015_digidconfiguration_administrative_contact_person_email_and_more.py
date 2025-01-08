# Generated by Django 4.2.13 on 2025-01-07 14:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "digid_eherkenning",
            "0014_alter_eherkenningconfiguration_digest_algorithm_and_more",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="digidconfiguration",
            name="administrative_contact_person_email",
            field=models.CharField(
                blank=True,
                help_text="Email address of the administrative contact person responsible for this DigiD/eHerkenning/eIDAS setup. For it to show up in the metadata, you should also specify the phone number.",
                max_length=100,
                verbose_name="administrative contact: email",
            ),
        ),
        migrations.AddField(
            model_name="digidconfiguration",
            name="administrative_contact_person_telephone",
            field=models.CharField(
                blank=True,
                help_text="Telephone number of the administrative contact person responsible for this DigiD/eHerkenning/eIDAS setup. For it to show up in the metadata, you should also specify the email address.",
                max_length=100,
                verbose_name="administrative contact: phone number",
            ),
        ),
        migrations.AddField(
            model_name="eherkenningconfiguration",
            name="administrative_contact_person_email",
            field=models.CharField(
                blank=True,
                help_text="Email address of the administrative contact person responsible for this DigiD/eHerkenning/eIDAS setup. For it to show up in the metadata, you should also specify the phone number.",
                max_length=100,
                verbose_name="administrative contact: email",
            ),
        ),
        migrations.AddField(
            model_name="eherkenningconfiguration",
            name="administrative_contact_person_telephone",
            field=models.CharField(
                blank=True,
                help_text="Telephone number of the administrative contact person responsible for this DigiD/eHerkenning/eIDAS setup. For it to show up in the metadata, you should also specify the email address.",
                max_length=100,
                verbose_name="administrative contact: phone number",
            ),
        ),
        migrations.AlterField(
            model_name="digidconfiguration",
            name="technical_contact_person_telephone",
            field=models.CharField(
                blank=True,
                help_text="Telephone number of the technical person responsible for this DigiD/eHerkenning/eIDAS setup. For it to show up in the metadata, you should also specify the email address.",
                max_length=100,
                verbose_name="technical contact: phone number",
            ),
        ),
        migrations.AlterField(
            model_name="eherkenningconfiguration",
            name="technical_contact_person_telephone",
            field=models.CharField(
                blank=True,
                help_text="Telephone number of the technical person responsible for this DigiD/eHerkenning/eIDAS setup. For it to show up in the metadata, you should also specify the email address.",
                max_length=100,
                verbose_name="technical contact: phone number",
            ),
        ),
    ]
