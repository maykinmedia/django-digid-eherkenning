=========
Changelog
=========

0.5.0 (2022-??-??)
==================

:boom: Breaking changes :warning: !

* Moved configuration of DigiD/eHerkenning/eIDAS to the admin. The ``DIGID`` and
  ``EHERKENNING`` settings no longer work.

  - in particular, the ``login_url`` key within these settings is not supported anymore,
    specify Django's ``LOGIN_URL`` setting instead or use the ``RelayState`` GET
    parameter

* Some default values have changed:

  - ``want_assertions_signed``: ``False`` -> ``True``
  - ``digestAlgorithm``: empty -> ``"http://www.w3.org/2000/09/xmldsig#sha1"``

* The DigiD ``session_age`` parameter used to be opt-in. This now defaults to 15 minutes
  (the maximum duration according to "DigiDCheck 2.2 T14 -- Sessieduur") through the
  ``DIGID_SESSION_AGE`` setting.

* Dropped support for Django 2.2 which is EOL

* Custom subclasses of ``digid_eherkenning.saml2.base.BaseSaml2Client`` need to implement
  the ``conf`` property - the ``__init__`` method no longer accepts a config dict.

0.4.1 (2022-07-12)
==================

* Supported single logout:

  * Added Digid logout view for Sp-initiated logout
  * Added Didid callback view for Sp-initiated logout with HTTP-redirect binding
  * Added Digid callback view for Idp-initiated logout with SOAP binding
  * Generated metadata with two single logout endpoints

0.4.0 (2022-06-23)
==================

* Added ``slo`` required parameter for Digid metadata generation as a first step to support single logout.


0.3.3 (2022-06-15)
==================

* Update to include locale files for translations

0.3.2 (2022-06-14)
==================

* Updated DigiD error messages to comply with Logius specifications

0.3.1 (2022-04-21)
==================

* Removed Jenkins related files
* The content-type header used during the resolve artifact request was made configurable.

0.3.0 (2022-02-25)
==================

We decided to better our lives and properly structure and publish this package :tada:

* Made Github the primary repository and Bitbucket a mirror
* Fixed Tox configuration
* Explicitly support Python 3.7, 3.8 and 3.9
* Explicitly support Django 2.2 and 3.2
* Set up Github workflows/actions for CI
* Cleaned up package metadata
* Cleaned up README
* Formatted code with isort and black

0.2.0 and earlier
=================

Sorry, no history except the commit history available!
