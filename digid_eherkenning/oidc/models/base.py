from copy import deepcopy
from typing import TypedDict

from django.conf import settings
from django.db import models
from django.utils.functional import classproperty
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import JSONField
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
    def decorator(cls: type[BaseConfig]):
        # set the choices for the default_loa
        default_loa_field = cls._meta.get_field("default_loa")
        assert isinstance(default_loa_field, models.CharField)
        default_loa_field.choices = choicesCls.choices

        # specify the choices for the JSONField schema
        loa_mapping_field = cls._meta.get_field("loa_value_mapping")
        assert isinstance(loa_mapping_field, JSONField)
        new_schema = deepcopy(loa_mapping_field.schema)
        new_schema["items"]["properties"]["to"]["choices"] = [
            {"value": val, "title": label} for val, label in choicesCls.choices
        ]
        loa_mapping_field.schema = new_schema

        return cls

    return decorator


LOA_MAPPING_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["from", "to"],
        "properties": {
            "from": {
                "anyOf": [
                    {
                        "type": "string",
                        "title": _("String value"),
                    },
                    {
                        "type": "number",
                        "title": _("Number value"),
                    },
                ],
            },
            "to": {
                "type": "string",
            },
        },
        "additionalProperties": False,
    },
}


class ClaimConfiguration(TypedDict):
    field: str  # model field name
    required: bool


class BaseConfig(OpenIDConnectConfigBase):
    """
    Base configuration for DigiD/eHerkenning authentication via OpenID Connect.
    """

    loa_claim = ClaimField(
        verbose_name=_("LoA claim"),
        default=None,
        help_text=_(
            "Name of the claim holding the level of assurance. If left empty, it is "
            "assumed there is no LOA claim and the configured fallback value will be "
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

    loa_value_mapping = JSONField(
        _("loa mapping"),
        schema=LOA_MAPPING_SCHEMA,
        default=list,
        blank=True,
        help_text=_(
            "Level of assurance claim value mappings. Useful if the values in the LOA "
            "claim are proprietary, so you can translate them into their standardized "
            "identifiers."
        ),
    )

    CLAIMS_CONFIGURATION: tuple[ClaimConfiguration, ...]

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
