# Generated by Django 4.2.6 on 2023-10-20 08:40

from django.db import migrations, models

import privates.fields
import privates.storages


class Migration(migrations.Migration):
    dependencies = [
        (
            "digid_eherkenning",
            "0005_alter_eherkenningconfiguration_eh_service_instance_uuid_and_more",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="digidconfiguration",
            name="metadata_file_source",
            field=models.URLField(
                default="",
                help_text="The URL-source where the XML metadata file can be retrieved from.",
                max_length=255,
                verbose_name="metadata file(XML) URL",
            ),
        ),
        migrations.AddField(
            model_name="eherkenningconfiguration",
            name="metadata_file_source",
            field=models.URLField(
                default="",
                help_text="The URL-source where the XML metadata file can be retrieved from.",
                max_length=255,
                verbose_name="metadata file(XML) URL",
            ),
        ),
        migrations.AlterField(
            model_name="digidconfiguration",
            name="idp_metadata_file",
            field=privates.fields.PrivateMediaFileField(
                blank=True,
                help_text="The metadata file of the identity provider. This is auto populated from the configured source URL.",
                storage=privates.storages.PrivateMediaFileSystemStorage(),
                upload_to="",
                verbose_name="identity provider metadata",
            ),
        ),
        migrations.AlterField(
            model_name="digidconfiguration",
            name="idp_service_entity_id",
            field=models.CharField(
                blank=True,
                help_text="Example value: 'https://was-preprod1.digid.nl/saml/idp/metadata'. Note that this must match the 'entityID' attribute on the 'md:EntityDescriptor' node found in the Identity Provider's metadata. This is auto populated from the configured source URL.",
                max_length=255,
                verbose_name="identity provider service entity ID",
            ),
        ),
        migrations.AlterField(
            model_name="eherkenningconfiguration",
            name="idp_metadata_file",
            field=privates.fields.PrivateMediaFileField(
                blank=True,
                help_text="The metadata file of the identity provider. This is auto populated from the configured source URL.",
                storage=privates.storages.PrivateMediaFileSystemStorage(),
                upload_to="",
                verbose_name="identity provider metadata",
            ),
        ),
        migrations.AlterField(
            model_name="eherkenningconfiguration",
            name="idp_service_entity_id",
            field=models.CharField(
                blank=True,
                help_text="Example value: 'https://was-preprod1.digid.nl/saml/idp/metadata'. Note that this must match the 'entityID' attribute on the 'md:EntityDescriptor' node found in the Identity Provider's metadata. This is auto populated from the configured source URL.",
                max_length=255,
                verbose_name="identity provider service entity ID",
            ),
        ),
    ]
