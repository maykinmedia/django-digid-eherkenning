from django.conf.urls import url

from . import views

app_name = "eherkenning"

urlpatterns = [
    url(r"login/", views.eHerkenningLoginView.as_view(), name="login"),
    url(r"acs/", views.eHerkenningAssertionConsumerServiceView.as_view(), name="acs"),
]
