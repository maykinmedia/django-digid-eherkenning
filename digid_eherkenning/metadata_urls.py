from django.urls import path

from .models import DigidMetadataConfiguration, EherkenningMetadataConfiguration
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
            config_model=DigidMetadataConfiguration,
            metadata_generator=generate_digid_metadata,
        ),
        name="digid",
    ),
    path(
        "eherkenning",
        MetadataView.as_view(
            config_model=EherkenningMetadataConfiguration,
            metadata_generator=generate_eherkenning_metadata,
        ),
        name="eherkenning",
    ),
    path(
        "eherkenning/dienstcatalogus",
        MetadataView.as_view(
            config_model=EherkenningMetadataConfiguration,
            metadata_generator=generate_dienst_catalogus_metadata,
        ),
        name="eh-dienstcatalogus",
    ),
]
