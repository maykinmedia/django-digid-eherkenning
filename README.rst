========================
django-digid-eherkenning
========================

:Version: 0.4.1
:Source: https://github.com/maykinmedia/django-digid-eherkenning
:Keywords: django, authentication, digid, eherkenning, eidas, dutch, nl, netherlands
:PythonVersion: 3.7+

|build-status| |code-quality| |black| |coverage| |docs|

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

* Python 3.7 or newer
* setuptools 30.3.0 or above
* Django 3.2

Install
-------

Install with pip:

.. code-block:: bash

    pip install django-digid-eherkenning

Add the library and its dependencies to your ``INSTALLED_APPS``:

.. code-block:: python

    INSTALLED_APPS = [
        ...,
        # required for digid-eherkenning
        "privates",
        "simple_certmanager",
        "solo",
        "digid_eherkenning",
        ...,
    ]

The ``sessionprofile`` dependency is required if you want to use DigiD Single Logout -
it is used to keep track of a user's sessions.

**Creating local users**

If you want to create local users as part of the authentication flow, add the
authentication backend to the settings:

.. code-block:: py

    AUTHENTICATION_BACKENDS = [
        ...,
        "digid_eherkenning.backends.DigiDBackend",
        ...,
    ]

**DigiD Single Logout**

DigiD single logout requires the ``sessionprofile`` dependency (automatically installed
alongside).

Add it to your ``INSTALLED_APPS``:

.. code-block:: python

    INSTALLED_APPS = [
        ...,
        # required for digid-eherkenning
        "privates",
        "simple_certmanager",
        "solo",
        # for DigiD single logout
        "sessionprofile",
        "digid_eherkenning",
        ...,
    ]

And add the middleware before Django's ``SessionMiddleware``:

.. code-block:: python
    :linenos:
    :emphasize-lines: 4,5

    MIDDLEWARE = [
        ...,
        "django.middleware.security.SecurityMiddleware",
        "sessionprofile.middleware.SessionProfileMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        ...,
    ]

**Registering URLs**

Finally, add the URL patterns to your root ``urls.py``:

.. code-block:: py

    from django.urls import path, include


    urlpatterns = [
        ...,
        path("", include("digid_eherkenning.urls")),
        ...,
    ]


The ``urls`` module exposes DigiD, eHerkenning and the metadata views. If desired,
you can also include the relevant aspects - see ``digid_eherkenning.urls`` for the
available URL modules.

Configuration
-------------

DigiD and eHerkenning are configured in the admin. Additionally, you can use the
metadata generation commands with the ``--save-config`` option to persist command line
configuration into the database.

.. note::

    The ``signature_algorithm`` configuration parameter is used only for requests with
    HTTP Redirect binding. Login request with HTTP Post binding uses the
    ``http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`` algorithm.


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


Metadata generation
===================

The easiest way to obtain the metadata is by editing the configuration of each
flow (DigiD, eHerkenning/eIDAS) in the admin. This also covers the eHerkenning
dienstcatalogus.

The configuration admin provides links to view the metadata in the browser (or
download it using cURL or similar tools).

.. note:: You may want to apply rate-limiting to this metadata endpoints at the
   webserver level. The metadata is generated on the fly and may be a source of
   Denial-Of-Service attacks.

   For convenience reasons these URLs are *public* so they can easily be shared with
   the identity providers.

If you wish, you can still use management commands to generate the metadata:

* ``generate_digid_metadata``
* ``generate_eherkenning_metadata``
* ``generate_eherkenning_dienstcatalogus``

For details, call:

.. code-block:: bash

    python manage.py <command> --help

.. note:: Tip: if you use the ``--save-config`` option, you can update the admin
   configuration from the command line.

Specific broker settings
========================

From 1st of April 2022 certain eHerkenning brokers like OneWelcome and Signicat,
require that the artifact resolution request has the content-type header
``text/xml`` instead of ``application/soap+xml``. This can be configured in the admin
and management commands.

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

Developers / contributors
=========================

Setting up the project for local development with all development dependencies is a
matter of installing the package with all extras:

.. code-block:: bash

    pip install -e .[tests,pep8,coverage,docs,release]

Then you can run tests with:

.. code-block:: bash

    pytest

To run all tests and checks on all supported environments:

.. code-block:: bash

    tox

Local development server
------------------------

You can spin up a local development server using the tests configuration:

.. code-block:: bash

    export DJANGO_SETTINGS_MODULE=testapp.settings
    django-admin migrate
    django-admin runserver


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

.. |docs| image:: https://readthedocs.org/projects/django-digid-eherkenning/badge/?version=latest
    :target: https://django-digid-eherkenning.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. |python-versions| image:: https://img.shields.io/pypi/pyversions/django-digid-eherkenning.svg

.. |django-versions| image:: https://img.shields.io/pypi/djversions/django-digid-eherkenning.svg

.. |pypi-version| image:: https://img.shields.io/pypi/v/django-digid-eherkenning.svg
    :target: https://pypi.org/project/django-digid-eherkenning/
