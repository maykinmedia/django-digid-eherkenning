.. _brokers:

=======
Brokers
=======

Artifact resolution content type
================================

From 1st of April 2022 certain eHerkenning and DigiD brokers like OneWelcome and Signicat,
require that the artifact resolution request has the content-type header
``text/xml`` instead of ``application/soap+xml``. This can be configured in the admin
and :ref:`management commands<cli>`.
