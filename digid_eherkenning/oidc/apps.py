from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class OIDCAppConfig(AppConfig):
    name = "digid_eherkenning.oidc"
    verbose_name = _("DigiD & eHerkenning via OpenID Connect")
    # can't change this label because of existing migrations in Open Forms/Open Inwoner
    label = "digid_eherkenning_oidc_generics"
    default_auto_field = "django.db.models.AutoField"
