.. _developers:

=======================
Developer documentation
=======================

This documentation section is aimed at developers on the library itself rather than
developers integrating the library.

Setting up the project
======================

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


Background information
======================

Information that was at some point relevant and may document certain choices can
be found in ``information.md`` in the root of the repository.

Bitbucket mirror
================

This project was originally on Bitbucket and closed source. The Bitbucket project still
exists, but only as a mirror of the Github repository. All future development must
happen on Github.

Bitbucket mirror: https://bitbucket.org/maykinmedia/django-digid-eherkenning/
