from django.urls import path

from . import views

urlpatterns = [
    path("digid/metadata", views.get_xml_digid_metadata, name="digid_metadata"),
    path(
        "eherkenning/metadata",
        views.get_xml_eherkenning_metadata,
        name="eherkenning_metadata",
    ),
    path(
        "eherkenning/diesnt-catalogus-metadata",
        views.get_xml_eherkenning_dienstcatalogus_metadata,
        name="eherkenning_diesntcatalogus_metadata",
    ),
]
