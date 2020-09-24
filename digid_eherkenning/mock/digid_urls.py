from django.conf.urls import url

from digid_eherkenning.mock.views.digid import (
    DigiDLoginMockView,
    DigiDAssertionConsumerServiceMockView,
)

"""
this is a mock replacement for the regular digid_urls.py
"""

app_name = "digid"

urlpatterns = (
    url(r"^login/", DigiDLoginMockView.as_view(), name="login"),
    url(r"^acs/", DigiDAssertionConsumerServiceMockView.as_view(), name="acs"),
)
