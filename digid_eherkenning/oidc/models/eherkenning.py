from django.db import models

from typing_extensions import deprecated


@deprecated(
    "Left here so that proxy models that in the migrations have "
    'bases=("digid_eherkenning_oidc_generics.eherkenningconfig",) can still run their migrations.'
)
class EHerkenningConfig(models.Model):  # noqa: DJ008
    class Meta:
        managed = False


@deprecated(
    "Left here so that proxy models that in the migrations have "
    'bases=("digid_eherkenning_oidc_generics.eherkenningbewindvoeringconfig",) can still run their migrations.'
)
class EHerkenningBewindvoeringConfig(models.Model):  # noqa: DJ008
    class Meta:
        managed = False
