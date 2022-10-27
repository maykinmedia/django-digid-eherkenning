from django.urls import include, path

# Default URL patterns - you can break this out in the individual modules if preferred.

urlpatterns = [
    path("digid/", include("digid_eherkenning.digid_urls")),
    path("eherkenning/", include("digid_eherkenning.eherkenning_urls")),
    path("metadata/", include("digid_eherkenning.metadata_urls")),
]
