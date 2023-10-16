.. _settings:

=============
Configuration
=============

Security considerations
-----------------------

**Client IP address**

django-digid-eherkenning extracts the client IP address from the ``X-Forwarded-For``
HTTP request header. This is a common and popular header for reverse-proxy
configurations, however, it **can** be spoofed by the end-user.

Users of this library are responsible for sanitizing the value of this header. If
possible, configure your web-server to set this header rather than append to it,
or apply other sanitations to drop untrusted entries/parts.

If this header is not set or empty, we instead get the value from ``REMOTE_ADDR``.

.. note:: django-ipware is **not** suitable for security-sensitive usage as it does a
   best-effort attempt at obtaining the client IP.

**Protecting metadata endpoints**

The metadata URLs are open by design to facilitate sharing these URLs with identity
providers or other interested parties. Because the metadata is generated on the fly,
there is a Denial-of-Service risk. We recommend to protect these URLs at the web-server
level by:

* applying an IP address allow-list
* applying HTTP Basic Auth
* setting up rate-limiting

This concerns the following paths:

* ``reverse("metadata:digid")``
* ``reverse("metadata:eherkenning")``
* ``reverse("metadata:eh-dienstcatalogus")``


Django settings
---------------

.. warning:: Before 0.5.0, django-digid-eherkenning was settings driven. This has been
   moved to database configuration. The ``DIGID`` and ``EHERKENNING`` settings have been
   removed.


``DIGID_SESSION_AGE``
  Maximum duration that a session is valid for when authenticating with DigiD, in
  seconds. Defaults to 900 (15 minutes).

  DigiD requires sessions to expire after 15 minutes or less of inactivity.

  .. note:: This setting is a last resort and it will expire after 15 minutes even if
     there is user activity. Typically you want to define a middleware in your project
     to extend the session duration while there is still activity.

``METADATA_URLS_CACHE_TIMEOUT``
  The library uses django cache in order to store some useful urls. This prevents reading an XML file
  if this has not been updated. Defaults to 86400 (1 day).
