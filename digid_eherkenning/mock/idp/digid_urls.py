from django.urls import path

from digid_eherkenning.mock.idp.views.digid import (
    DigiDMockIDPLoginView,
    DigiDMockIDPPasswordLoginView,
)

app_name = "digid-mock"

urlpatterns = [
    path("inloggen/", DigiDMockIDPLoginView.as_view(), name="login"),
    path("inloggen_ww/", DigiDMockIDPPasswordLoginView.as_view(), name="password"),
]
