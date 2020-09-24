from django.contrib import admin
from django.conf.urls import url, include

urlpatterns = [
    url("digid/", include("digid_eherkenning.digid_urls")),
    url("eherkenning/", include("digid_eherkenning.eherkenning_urls")),
    url("admin/", admin.site.urls),
]
