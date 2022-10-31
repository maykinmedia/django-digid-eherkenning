.. _mocks:

===============
Mock login flow
===============

For development and demonstration purposes you can swap-in a mockup Digid login flow
that accepts any BSN and doesn't require an actual DigiD metadata configuration.

In the login view username field you can enter any integer up to 9 digits
(and a random password) to be used as the BSN in the authentication backend.

Swap the authentication backend for the mock version:

.. code-block:: py

    AUTHENTICATION_BACKENDS = [
        "digid_eherkenning.backends.mock.DigiDBackend",
    ]

Swap the digid url patterns for the mock version:

.. code-block:: py

    urlpatterns = [
        ...,
        path("digid/", include("digid_eherkenning.mock.digid_urls")),
        ...,
    ]

Additionally add the URLs for the mock IDP service to run in the same runserver instance:

.. code-block:: py

    urlpatterns = [
        ...,
        path("digid/idp/", include("digid_eherkenning.mock.idp.digid_urls")),
        ...,
    ]

For settings to control mock behaviour see ``digid_eherkenning/mock/config.py``.
