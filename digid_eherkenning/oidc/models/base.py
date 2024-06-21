from django.conf import settings
from django.db import models
from django.utils.functional import classproperty
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

from mozilla_django_oidc_db.fields import ClaimField
from mozilla_django_oidc_db.models import OpenIDConnectConfigBase


def get_default_scopes_bsn():
    """
    Returns the default scopes to request for OpenID Connect logins for DigiD.
    """
    return ["openid", "bsn"]


def get_default_scopes_kvk():
    """
    Returns the default scopes to request for OpenID Connect logins for eHerkenning.
    """
    return ["openid", "kvk"]


def default_loa_choices(choicesCls: type[models.TextChoices]):
    def decorator(cls: type[models.Model]):
        field = cls._meta.get_field("default_loa")
        field.choices = choicesCls.choices
        return cls

    return decorator


class BaseConfig(OpenIDConnectConfigBase):
    """
    Base configuration for DigiD/eHerkenning authentication via OpenID Connect.
    """

    loa_claim = ClaimField(
        verbose_name=_("LoA claim"),
        default=None,
        help_text=_(
            "Name of the claim holding the level of assurance. If left empty, it is "
            "assumed there is no LOA claim and the configured callback value will be "
            "used."
        ),
        null=True,
        blank=True,
    )
    default_loa = models.CharField(
        _("default LOA"),
        max_length=100,
        blank=True,
        choices=tuple(),  # set dynamically via the default_loa_choices decorator
        help_text=_(
            "Fallback level of assurance, in case no claim value could be extracted."
        ),
    )

    class Meta:
        abstract = True

    @classproperty
    def oidcdb_check_idp_availability(cls) -> bool:
        return True

    def get_callback_view(self):
        configured_setting = getattr(
            settings,
            "DIGID_EHERKENNING_OIDC_CALLBACK_VIEW",
            "digid_eherkenning.oidc.views.default_callback_view",
        )
        return import_string(configured_setting)
