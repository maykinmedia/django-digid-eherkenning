.. _oidc:

======================================
DigiD & eHerkenning via OpenID Connect
======================================

Some brokers expose a DigiD/eHerkenning identity provider via the OpenID Connect
protocol. The :mod:`digid_eherkenning.oidc` package provides support for this.

The tooling for this builds on top of `mozilla-django-oidc-db`_, so those installation
instructions are also relevant.

Installation
============

Install with the optional dependency group:

.. code-block:: bash

    pip install django-digid-eherkenning[oidc]

and add the necessary packages to ``INSTALLED_APPS``:

.. code-block:: python

    INSTALLED_APPS = [
        ...,
        "privates",
        "simple_certmanager",
        "django_jsonform",
        "solo",
        "mozilla_django_oidc",
        "mozilla_django_oidc_db",
        "digid_eherkenning",
        "digid_eherkenning.oidc",
        ...,
    ]

Make sure to follow mozilla-django-oidc-db's installation instructions too.

Optionally you can point to an alternative callback view to use via the
``DIGID_EHERKENNING_OIDC_CALLBACK_VIEW`` setting, which defaults to
``"digid_eherkenning.oidc.views.default_callback_view"``.

Authentication backend
======================

If you wish to create Django users for the users authenticating via OIDC, you need to
set up an authentication backend and add it to ``settings.AUTHENTICATION_BACKENDS``.

We recommend to subclass :class:`mozilla_django_oidc_db.backends.OIDCAuthenticationBackend`,
and you can mix in some utilities from :mod:`digid_eherkenning.backends`.

This package does not (yet) ship a default backend for user creation.

Configuration
=============

The OpenID Connect configuration is managed in the admin, where you control the Relying
Party aspects.

Views
=====

This package exposes initialization views, which you can hook up to your URL conf, or
incorporate in your own initialization flow views:

* :attr:`digid_eherkenning.oidc.views.digid_init`
* :attr:`digid_eherkenning.oidc.views.eh_init`
* :attr:`digid_eherkenning.oidc.views.digid_machtigen_init`
* :attr:`digid_eherkenning.oidc.views.eh_bewindvoering_init`

.. _mozilla-django-oidc-db: https://mozilla-django-oidc-db.readthedocs.io/en/latest/
