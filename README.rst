========================
django-digid-eherkenning
========================

:Version: 0.4.0
:Source: https://github.com/maykinmedia/django-digid-eherkenning
:Keywords: django, authentication, digid, eherkenning, eidas, dutch, nl, netherlands
:PythonVersion: 3.7+

|build-status| |code-quality| |black| |coverage|

|python-versions| |django-versions| |pypi-version|

A Django app for DigiD/eHerkenning authentication flows

.. contents::

.. section-numbering::

Features
========

* SAML-based DigiD authentication flow
* SAML-based eHerkenning authentication flow
* Custom Django authentication backend
* Extensible

Installation
============

Requirements
------------

* Python 3.7 or above
* setuptools 30.3.0 or above
* Django 2.2 or newer


Install
-------

Install with pip:

.. code-block:: bash

    pip install git+https://github.com/maykinmedia/python3-saml@maykin#egg=python3-saml
    pip install django-digid-eherkenning

Add ``digid_eherkenning`` to the ``INSTALLED_APPS`` in your Django project's settings:

.. code-block:: py

    INSTALLED_APPS = [
        ...,
        "digid_eherkenning",
        ...,
    ]

If you want to create local users as part of the authentication flow, add the
authentication backend to the settings:

.. code-block:: py

    AUTHENTICATION_BACKENDS = [
        ...,
        "digid_eherkenning.backends.DigiDBackend",
        ...,
    ]

Finally, at the URL patterns to your root ``urls.py``:

.. code-block:: py

    from django.urls import path, include


    urlpatterns = [
        ...,
        path("digid/", include("digid_eherkenning.digid_urls")),
        ...,
    ]

Usage
=====

You can now display login URLs by reversing the appropriate URL:

.. code-block:: py

    reverse("digid:login")

or in templates:

.. code-block:: django

    {% url 'digid:login' %}


Mock login flow
---------------

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

Generating the DigiD metadata
-----------------------------

The metadata for DigiD can be generated with the following command:

.. code-block:: bash

    python manage.py generate_digid_metadata \
        --want_assertions_encrypted \
        --want_assertions_signed \
        --key_file /path/test.key \
        --cert_file /path/test.certificate \
        --signature_algorithm "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" \
        --digest_algorithm "http://www.w3.org/2001/04/xmlenc#sha256" \
        --entity_id http://test-url.nl \
        --base_url http://test-url.nl \
        --service_name "Test name" \
        --service_description "Test description" \
        --attribute_consuming_service_index 9050 \
        --technical_contact_person_telephone 06123123123 \
        --technical_contact_person_email test@test.nl \
        --organization_name "Test organisation" \
        --organization_url http://test-organisation.nl \
        --slo

Generating eHerkenning/eIDAS metadata
-------------------------------------

The metadata for eHerkenning and eIDAS can be generated with the following command:

.. code-block:: bash

    python manage.py generate_eherkenning_metadata \
        --want_assertions_encrypted \
        --want_assertions_signed \
        --key_file /path/test.key \
        --cert_file /path/test.certificate \
        --signature_algorithm "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" \
        --digest_algorithm "http://www.w3.org/2001/04/xmlenc#sha256" \
        --entity_id http://test-url.nl \
        --base_url http://test-url.nl \
        --service_name "Test name" \
        --service_description "Test description" \
        --eh_attribute_consuming_service_index 9052 \
        --eidas_attribute_consuming_service_index 9053 \
        --oin 00000001112223330000 \
        --technical_contact_person_telephone 06123123123 \
        --technical_contact_person_email test@test.nl \
        --organization_name "Test organisation" \
        --organization_url http://test-organisation.nl

For information about each option, use:

.. code-block:: bash

    python manage.py generate_eherkenning_metadata --help

To generate the dienstcatalogus:

.. code-block:: bash

    python manage.py generate_eherkenning_dienstcatalogus  \
        --key_file /path/test.key \
        --cert_file /path/test.certificate \
        --entity_id http://test-url.nl \
        --base_url http://test-url.nl \
        --service_name "Test name" \
        --service_description "Test description" \
        --eh_attribute_consuming_service_index 9052 \
        --eidas_attribute_consuming_service_index 9053 \
        --oin 00000001112223330000 \
        --privacy_policy http://test-url.nl/privacy \
        --makelaar_id 00000003332223330000 \
        --organization_name "Test Organisation"

Specific broker settings
========================

From 1st of April 2022 certain eHerkenning brokers like OneWelcome and Signicat, require that the artifact resolution
request has the content-type header ``text/xml`` instead of ``application/soap+xml``. This can be configured by including
the following parameter in the ``EHERKENNING`` django setting:

.. code-block:: python

    EHERKENNING = {
        ...
        "artifact_resolve_content_type": "text/xml",
        ...
    }

Background information
======================

Information that was at some point relevant and may document certain choices can
be found in ``information.md``.

Bitbucket mirror
================

This project was originally on Bitbucket and closed source. The Bitbucket project still
exists, but only as a mirror of the Github repository. All future development must
happen on Github.

Bitbucket mirror: https://bitbucket.org/maykinmedia/django-digid-eherkenning/


.. |build-status| image:: https://github.com/maykinmedia/django-digid-eherkenning/workflows/Run%20CI/badge.svg
    :alt: Build status
    :target: https://github.com/maykinmedia/django-digid-eherkenning/actions?query=workflow%3A%22Run+CI%22

.. |code-quality| image:: https://github.com/maykinmedia/django-digid-eherkenning/workflows/Code%20quality%20checks/badge.svg
     :alt: Code quality checks
     :target: https://github.com/maykinmedia/django-digid-eherkenning/actions?query=workflow%3A%22Code+quality+checks%22

.. |black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

.. |coverage| image:: https://codecov.io/gh/maykinmedia/django-digid-eherkenning/branch/master/graph/badge.svg?token=LNK592C9B2
    :target: https://codecov.io/gh/maykinmedia/django-digid-eherkenning
    :alt: Coverage status

.. |python-versions| image:: https://img.shields.io/pypi/pyversions/django-digid-eherkenning.svg

.. |django-versions| image:: https://img.shields.io/pypi/djversions/django-digid-eherkenning.svg

.. |pypi-version| image:: https://img.shields.io/pypi/v/django-digid-eherkenning.svg
    :target: https://pypi.org/project/django-digid-eherkenning/
