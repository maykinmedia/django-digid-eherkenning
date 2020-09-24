from django.conf.urls import include, url

"""
urls to setup a minimal mock IDP server
"""

urlpatterns = [
    url("^digid/", include("digid_eherkenning.mock.idp.digid_urls")),
]
