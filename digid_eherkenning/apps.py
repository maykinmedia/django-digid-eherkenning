from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class DigidEherkenningConfig(AppConfig):
    name = "digid_eherkenning"
    verbose_label = _("DigiD, eHerkenning & eIDAS")
    default_auto_field = "django.db.models.AutoField"
