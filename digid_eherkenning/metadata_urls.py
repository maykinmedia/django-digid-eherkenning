from django.urls import path

from . import views

app_name = "metadata"

urlpatterns = [
    path("digid", views.get_xml_digid_metadata, name="digid"),
    path("eherkenning", views.get_xml_eherkenning_metadata, name="eherkenning"),
    path(
        "eherkenning/dienstcatalogus",
        views.get_xml_eherkenning_dienstcatalogus_metadata,
        name="eh-dienstcatalogus",
    ),
]
