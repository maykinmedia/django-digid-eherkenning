from django.urls import path

from digid_eherkenning.mock.idp.views.digid import (  # DigiDMockIDPPasswordLoginView,
    DigiDMockIDPBSNLoginView,
    DigiDMockIDPLoginView,
)

app_name = "digid-mock"

urlpatterns = [
    path("inloggen/", DigiDMockIDPLoginView.as_view(), name="login"),
    path("inloggen_ww/", DigiDMockIDPBSNLoginView.as_view(), name="bsn"),
]
