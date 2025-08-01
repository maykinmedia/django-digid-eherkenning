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

    pip install -e .[tests,docs,release,oidc]

.. note::

    the OIDC code in this library is deprecated, but the ``mozilla_django_oidc_db`` 
    dependency is still needed for migrations.

Then you can run tests with:

.. code-block:: bash

    pytest

To run all tests and checks on all supported environments:

.. code-block:: bash

    tox

Local development server
------------------------

You can spin up a local development server using the tests configuration (from the root directory):

.. code-block:: bash

    export PYTHONPATH=$PYTHONPATH:`pwd`
    export DJANGO_SETTINGS_MODULE=tests.project.settings
    django-admin migrate
    django-admin runserver


Background information
======================

Information that was at some point relevant and may document certain choices can
be found in ``information.md`` in the root of the repository.
