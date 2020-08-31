from .settings import *

ROOT_URLCONF = "tests.project.mock_urls"

AUTHENTICATION_BACKENDS = [
    "digid_eherkenning.mock.backends.DigiDMockBackend",
]

DIGID_MOCK_APP_TITLE = 'DigiD Mock Demo'  # service name displayed in popup
DIGID_MOCK_RETURN_URL = reverse_lazy('test-success')  # url to redirect to after success
DIGID_MOCK_CANCEL_URL = reverse_lazy('test-index')  # url to navigate to when users clicks 'cancel/annuleren'
DIGID_MOCK_LOGIN_URL = None
