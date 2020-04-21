from django.conf.urls import url

from . import views

urlpatterns = [
    url(r"login/", views.LoginView.as_view(), name="saml2-login"),
    url(r"acs/", views.AssertionConsumerServiceView.as_view(), name="saml2-acs"),
]
