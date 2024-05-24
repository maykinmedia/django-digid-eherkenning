==========
Quickstart
==========

Installation
============

Requirements
------------

* See the badges for the supported Python and Django versions
* XML system packages, e.g. for Debian/Ubuntu:

    - ``libxml2-dev``
    - ``libxmlsec1-dev``
    - ``libxmlsec1-openssl``

Installation
------------

See :ref:`oidc` for configuring the OIDC flavour.

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
=============

DigiD and eHerkenning are configured in the admin. Additionally, you can use the
metadata generation commands with the ``--save-config`` option to persist command line
configuration into the database.

.. note::

    The ``signature_algorithm`` configuration parameter is used only for requests with
    HTTP Redirect binding. Login request with HTTP Post binding uses the
    ``http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`` algorithm.

Usage
=====

Admin integration
-----------------

In the admin you can now provide the DigiD and/or eHerkenning/eIDAS configuration, which
will be used at runtime and during metadata generation.

In your code
------------

You can now display login URLs by reversing the appropriate URL:

.. code-block:: py

    reverse("digid:login")

or in templates:

.. code-block:: django

    {% url 'digid:login' %}
