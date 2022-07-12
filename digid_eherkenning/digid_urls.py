from django.urls import path

from . import views

app_name = "digid"

urlpatterns = [
    path("login/", views.DigiDLoginView.as_view(), name="login"),
    path("acs/", views.DigiDAssertionConsumerServiceView.as_view(), name="acs"),
    path("logout/", views.DigiDLogoutView.as_view(), name="logout"),
    path(
        "slo/redirect/",
        views.DigidSingleLogoutRedirectView.as_view(),
        name="slo-redirect",
    ),
    path("slo/soap/", views.DigidSingleLogoutSoapView.as_view(), name="slo-soap"),
]
