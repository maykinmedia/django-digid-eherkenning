from .base import BaseConfig, get_default_scopes_bsn, get_default_scopes_kvk
from .digid import DigiDConfig, DigiDMachtigenConfig
from .eherkenning import EHerkenningBewindvoeringConfig, EHerkenningConfig

__all__ = [
    "get_default_scopes_bsn",
    "get_default_scopes_kvk",
    "BaseConfig",
    "DigiDConfig",
    "DigiDMachtigenConfig",
    "EHerkenningConfig",
    "EHerkenningBewindvoeringConfig",
]
