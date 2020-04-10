from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.LoginView.as_view(), name="saml2-login"),
    path("acs/", views.AssertionConsumerServiceView.as_view(), name="saml2-acs"),
]
