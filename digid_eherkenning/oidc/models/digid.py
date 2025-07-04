from django.db import models

from typing_extensions import deprecated


@deprecated(
    "Left here so that proxy models that in the migrations have "
    'bases=("digid_eherkenning_oidc_generics.digidconfig",) can still run their migrations.'
)
class DigiDConfig(models.Model):
    class Meta:
        managed = False


@deprecated(
    "Left here so that proxy models that in the migrations have "
    'bases=("digid_eherkenning_oidc_generics.digidmachtigenconfig",) can still run their migrations.'
)
class DigiDMachtigenConfig(models.Model):
    class Meta:
        managed = False
