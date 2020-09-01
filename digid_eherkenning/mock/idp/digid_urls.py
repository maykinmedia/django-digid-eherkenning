from django.conf.urls import url

from digid_eherkenning.mock.idp.views.digid import (
    DigiDMockIDPLoginView,
    DigiDMockIDPPasswordLoginView,
)

app_name = "digid-mock"

urlpatterns = [
    url(r"^inloggen/?$", DigiDMockIDPLoginView.as_view(), name="login"),
    url(r"^inloggen_ww/?$", DigiDMockIDPPasswordLoginView.as_view(), name="password"),
]
