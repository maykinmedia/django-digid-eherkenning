from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

# See `OINType` in eherkenning-dc.xml XSD
oin_validator = RegexValidator(
    regex=r"[0-9]{20}",
    message=_("A valid OIN consists of 20 digits."),
)
