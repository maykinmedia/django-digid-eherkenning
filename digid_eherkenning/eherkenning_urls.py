from django.urls import path

from . import views

app_name = "eherkenning"

urlpatterns = [
    path("login/", views.eHerkenningLoginView.as_view(), name="login"),
    path("acs/", views.eHerkenningAssertionConsumerServiceView.as_view(), name="acs"),
]
