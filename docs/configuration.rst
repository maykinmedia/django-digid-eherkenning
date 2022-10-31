.. _settings:

=============
Configuration
=============

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


