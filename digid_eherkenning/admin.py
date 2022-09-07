from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from solo.admin import SingletonModelAdmin

from .models import DigidMetadataConfiguration, EherkenningMetadataConfiguration


@admin.register(DigidMetadataConfiguration)
class DigidMetadataConfigurationAdmin(SingletonModelAdmin):
    pass


@admin.register(EherkenningMetadataConfiguration)
class EherkenningMetadataConfigurationAdmin(SingletonModelAdmin):
    pass
