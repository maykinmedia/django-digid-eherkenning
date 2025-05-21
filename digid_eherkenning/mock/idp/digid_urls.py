from django.urls import path

from digid_eherkenning.mock.idp.views.digid import (
    DigiDMockIDPBSNLoginView,
    DigiDMockIDPLoginView,
)

app_name = "digid-mock"

urlpatterns = [
    path("inloggen/", DigiDMockIDPLoginView.as_view(), name="login"),
    path("inloggen_bsn/", DigiDMockIDPBSNLoginView.as_view(), name="bsn"),
]
