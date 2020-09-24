from .settings import *

ROOT_URLCONF = "tests.project.mock_urls"

AUTHENTICATION_BACKENDS = [
    "digid_eherkenning.mock.backends.DigiDBackend",
]

DIGID_MOCK_APP_TITLE = "DigiD Mock Standalone Demo"  # service name displayed in popup
