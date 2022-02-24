from django.urls import path

from . import views

app_name = "digid"

urlpatterns = [
    path("login/", views.DigiDLoginView.as_view(), name="login"),
    path("acs/", views.DigiDAssertionConsumerServiceView.as_view(), name="acs"),
]
