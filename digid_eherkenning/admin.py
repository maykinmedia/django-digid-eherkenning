from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from solo.admin import SingletonModelAdmin

from .models.digid_metadata_config import DigidMetadataConfiguration
from .models.eherkenning_metadata_config import EherkenningMetadataConfiguration


@admin.register(DigidMetadataConfiguration)
class DigidMetadataConfigurationAdmin(SingletonModelAdmin):
    pass


@admin.register(EherkenningMetadataConfiguration)
class EherkenningMetadataConfigurationAdmin(SingletonModelAdmin):
    pass
