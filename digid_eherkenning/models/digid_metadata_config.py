from django.db import models
from django.utils.translation import gettext_lazy as _

from .metadata_config import MetadataConfiguration


class DigidMetadataConfiguration(MetadataConfiguration):

    slo = models.BooleanField(
        _("Single logout"),
        default=True,
        help_text=_("If enabled, Single Logout is supported"),
    )

    class Meta:
        verbose_name = _("Digid metadata configuration")
