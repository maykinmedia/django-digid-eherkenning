import os

from django.conf import settings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EHERKENNING_DS_XSD = os.path.join(BASE_DIR, "xsd", "eherkenning-dc.xml")

empty = object()

# Public settings
class Defaults:
    DIGID_SESSION_AGE: int = 60 * 15  # 15 minutes, in seconds


def get_setting(name: str):
    """
    Get the runtime setting value or use the default value if not specified.
    """
    value = getattr(settings, name, empty)
    if value is not empty:
        return value

    default = getattr(Defaults, name)
    return default
