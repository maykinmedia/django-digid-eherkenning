from .digid import (  # noqa
    DigiDAssertionConsumerServiceView,
    DigiDLoginView,
    DigiDLogoutView,
    DigidSingleLogoutRedirectView,
    DigidSingleLogoutSoapView,
    get_xml_digid_metadata,
)
from .eherkenning import (  # noqa
    eHerkenningAssertionConsumerServiceView,
    eHerkenningLoginView,
    get_xml_eherkenning_dienstcatalogus_metadata,
    get_xml_eherkenning_metadata,
)
