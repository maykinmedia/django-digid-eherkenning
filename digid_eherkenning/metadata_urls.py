from django.urls import path

from .models import DigidConfiguration, EherkenningConfiguration
from .saml2.digid import generate_digid_metadata
from .saml2.eherkenning import (
    generate_dienst_catalogus_metadata,
    generate_eherkenning_metadata,
)
from .views.metadata import MetadataView

app_name = "metadata"

urlpatterns = [
    path(
        "digid",
        MetadataView.as_view(
            config_model=DigidConfiguration,
            metadata_generator=generate_digid_metadata,
            filename="digid-metadata.xml",
        ),
        name="digid",
    ),
    path(
        "eherkenning",
        MetadataView.as_view(
            config_model=EherkenningConfiguration,
            metadata_generator=generate_eherkenning_metadata,
            filename="eh-metadata.xml",
        ),
        name="eherkenning",
    ),
    path(
        "eherkenning/dienstcatalogus",
        MetadataView.as_view(
            config_model=EherkenningConfiguration,
            metadata_generator=generate_dienst_catalogus_metadata,
            filename="dienstcatalogus.xml",
        ),
        name="eh-dienstcatalogus",
    ),
]
