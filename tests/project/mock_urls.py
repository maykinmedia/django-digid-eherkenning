from django.conf.urls import include, url
from django.contrib import admin

from tests.project.views import MockIndexView, MockSuccessView

urlpatterns = [
    url("digid/", include("digid_eherkenning.mock.digid_urls")),
    url("digid/idp/", include("digid_eherkenning.mock.idp.digid_urls")),
    url("admin/", admin.site.urls),
    url("success", MockSuccessView.as_view(), name='test-success'),
    url("^$", MockIndexView.as_view(), name='test-index'),
]
