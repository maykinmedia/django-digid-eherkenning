from django.urls import path

from digid_eherkenning.mock.views.digid import (
    DigiDAssertionConsumerServiceMockView,
    DigiDLoginMockView,
    DigiDLogoutMockView,
)

"""
this is a mock replacement for the regular digid_urls.py
"""

app_name = "digid"

urlpatterns = (
    path("login/", DigiDLoginMockView.as_view(), name="login"),
    path("acs/", DigiDAssertionConsumerServiceMockView.as_view(), name="acs"),
    path("logout/", DigiDLogoutMockView.as_view(), name="logout"),
)
