from django.contrib import admin
from django.urls import include, path

from tests.project.views import MockIndexView, MockSuccessView

urlpatterns = [
    path("digid/", include("digid_eherkenning.mock.digid_urls")),
    path("digid/idp/", include("digid_eherkenning.mock.idp.digid_urls")),
    path("admin/", admin.site.urls),
    path("success", MockSuccessView.as_view(), name="test-success"),
    path("", MockIndexView.as_view(), name="test-index"),
]
