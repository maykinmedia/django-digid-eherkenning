# Generated by Django 3.2.15 on 2022-10-20 10:29

from django.db import migrations, models

import privates.fields
import privates.storages


class Migration(migrations.Migration):

    dependencies = [
        ("digid_eherkenning", "0002_auto_20220907_0717"),
    ]

    operations = [
        migrations.AddField(
            model_name="digidmetadataconfiguration",
            name="idp_metadata_file",
            field=privates.fields.PrivateMediaFileField(
                default="",
                help_text="The metadata file of the identity provider",
                storage=privates.storages.PrivateMediaFileSystemStorage(),
                upload_to="",
                verbose_name="Identity Provider metadata file",
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="digidmetadataconfiguration",
            name="idp_service_entity_id",
            field=models.CharField(
                default="",
                help_text="Example value: 'https://was-preprod1.digid.nl/saml/idp/metadata'",
                max_length=255,
                verbose_name="Identity Provider service entity ID",
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="digidmetadataconfiguration",
            name="requested_attributes",
            field=models.JSONField(
                default=list,
                help_text="A list of strings with the requested attributes, e.g. '[\"bsn\"]'",
                verbose_name="requested attributes",
            ),
        ),
        migrations.AddField(
            model_name="eherkenningmetadataconfiguration",
            name="idp_metadata_file",
            field=privates.fields.PrivateMediaFileField(
                default="",
                help_text="The metadata file of the identity provider",
                storage=privates.storages.PrivateMediaFileSystemStorage(),
                upload_to="",
                verbose_name="Identity Provider metadata file",
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="eherkenningmetadataconfiguration",
            name="idp_service_entity_id",
            field=models.CharField(
                default="",
                help_text="Example value: 'https://was-preprod1.digid.nl/saml/idp/metadata'",
                max_length=255,
                verbose_name="Identity Provider service entity ID",
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="eherkenningmetadataconfiguration",
            name="requested_attributes",
            field=models.JSONField(
                default=list,
                help_text="A list of strings with the requested attributes, e.g. '[\"bsn\"]'",
                verbose_name="requested attributes",
            ),
        ),
    ]