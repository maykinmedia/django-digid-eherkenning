from django.urls import include, path

urlpatterns = [
    path("", include("digid_eherkenning.digid_urls")),
]
