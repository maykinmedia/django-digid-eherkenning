from django.db import models
from django.utils.translation import gettext_lazy as _

from .metadata_config import MetadataConfiguration


class EherkenningMetadataConfiguration(MetadataConfiguration):

    loa = models.CharField(
        _("Loa"),
        default="urn:etoegang:core:assurance-class:loa3",
        blank=True,
        help_text=_("Level of Assurance (LoA) to use for all the services."),
        max_length=100,
    )
    eh_attribute_consuming_service_index = models.CharField(
        _("eh attribute consumng service index"),
        blank=True,
        default="9052",
        help_text=_("Attribute consuming service index for the eHerkenning service"),
        max_length=100,
    )
    eidas_attribute_consuming_service_index = models.CharField(
        _("eidas attribute consumng service index"),
        blank=True,
        default="9053",
        help_text=_("Attribute consuming service index for the eHerkenning service"),
        max_length=100,
    )
    oin = models.CharField(
        _("Oin"),
        help_text=_("The OIN of the company providing the service."),
        max_length=100,
    )
    no_eidas = models.BooleanField(
        _("No eidas"),
        blank=True,
        default=False,
        help_text=_(
            "If True, then the service catalogue will contain only the eHerkenning service."
        ),
    )
    privacy_policy = models.URLField(
        _("Privacy policy"),
        help_text=_(
            "The URL where the privacy policy from the organisation providing the service can be found."
        ),
        max_length=100,
    )
    makelaar_id = models.CharField(
        _("Makelaar ID"),
        help_text=_("OIN of the broker used to set up eHerkenning/eIDAS."),
        max_length=100,
    )

    class Meta:
        verbose_name = _("Eherkenning metadata configuration")
