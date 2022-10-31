.. _cli:

======================
Command-line interface
======================

django-digid-eherkenning ships with a couple of Django management commands:

* ``generate_digid_metadata``
* ``generate_eherkenning_metadata``
* ``generate_eherkenning_dienstcatalogus``

For details, call:

.. code-block:: bash

    python manage.py <command> --help

.. note:: Tip: if you use the ``--save-config`` option, you can update the admin
   configuration from the command line.
