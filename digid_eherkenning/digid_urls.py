from django.conf.urls import url

from . import views

app_name = 'digid'

urlpatterns = [
    url(r"login/", views.DigiDLoginView.as_view(), name="login"),
    url(r"acs/", views.DigiDAssertionConsumerServiceView.as_view(), name="acs"),
]
