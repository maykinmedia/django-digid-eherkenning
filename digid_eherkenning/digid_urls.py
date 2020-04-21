from django.conf.urls import url

from . import views

app_name = 'digid'

urlpatterns = [
    url(r"login/", views.LoginView.as_view(), name="login"),
    url(r"acs/", views.AssertionConsumerServiceView.as_view(), name="acs"),
]
