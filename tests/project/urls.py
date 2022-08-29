from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("digid/", include("digid_eherkenning.digid_urls")),
    path("eherkenning/", include("digid_eherkenning.eherkenning_urls")),
    path("", include("digid_eherkenning.metadata_urls")),
    path("admin/", admin.site.urls),
]
