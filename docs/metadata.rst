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
