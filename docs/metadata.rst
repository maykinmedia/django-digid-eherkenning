.. _metadata:

===================
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

If you wish, you can still use :ref:`management commands<cli>` to generate the metadata.

eHerkenning / eIDAS
-------------------

.. _metadata_requested_attributes:

Configuring RequestedAttribute
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In the field ``RequestedAttribute`` one can specify all the attributes that may be
requested by the service when a company/person logs in with eHerkenning or eIDAS.

The values specified need to come from the Attribuutcatalogus_ (there are multiple
catalogues: 'generiek', 'natuurlijke personen' and 'non-natuurlijke personen').

In the admin, these can be specified as a list of dictionaries. For example, for eIDAS
one could use the following JSON to request the first name of the person who logged in:

.. code-block:: json

   [
     {
       "name": "urn:etoegang:1.9:attribute:FirstName",
       "required": true,
       "purpose_statements": {
         "en": "For testing purposes.",
         "nl": "Voor testdoeleinden."
       }
     }
   ]

.. warning:: YOU MAY NOT REQUEST ATTRIBUTES LISTED IN "Identificerende kenmerken". If
   you do so, the metadata will be rejected by the broker. In practice this means:

   * don't request the ``KVKNr`` attribute
   * don't request the ``Pseudo`` attribute
   * don't request the ``RSIN`` attribute
   * don't request the ``BSN`` attribute

   These attributes are pre-configured and will be returned without asking for them.

.. _Attribuutcatalogus: https://afsprakenstelsel.etoegang.nl/Startpagina/v3/attribuutcatalogus
