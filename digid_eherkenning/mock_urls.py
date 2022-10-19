from django.urls import include, path

"""
urls to setup a minimal mock IDP server
"""

urlpatterns = [
    path("digid/", include("digid_eherkenning.mock.idp.digid_urls")),
]
