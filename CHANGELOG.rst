=========
Changelog
=========

0.8.0 (2023-06-21)
==================

Feature release

* Added configurable Content-Type header for DigiD SAML
* Implemented a way to override the global configuration defaults for Level Of Assurance (LOA)
* [#30] Ensure generated metadata has xml tag
* [#35] Confirmed support for Django 4.2

0.7.0 (2023-02-21)
==================

Quality of life updates

* [#27] Removed Python 3.7 and 3.8 from test matrix (3.7 is EOL, 3.8 is not used in our
  envs anymore)
* [#25] Removed Django Choices usage in tests
* The post-binding form is now hidden from the end-user

0.6.0 (2023-02-16)
==================

Small housekeeping release

* Dropped django-choices dependency
* Updated codecov github action to v3
* Confirmed support for Django 4.0 and 4.1
* Format with latest version of black

0.5.1 (2022-11-02)
==================

Bugfix release

* Fixed missing migration due to changed help texts/labels in the models
* Added some robustness in metadata generation when the IDP configuration doesn't match
  the IDP metadata to prevent crashes

0.5.0 (2022-10-31)
==================

💥⚠️ Breaking changes ahead!

This release is an overhaul of the project configuration. We have moved away from
configuration via Django settings to configuration in the database. There is no
backwards compatible deprecation layer.

**Changes**

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
* Metadata generation can now be done on the fly, in the browser. You'll find links on
  the admin configuration pages.
* Re-organized the documentation, which is now hosted on readthedocs.
* The package metadata now contains all the dependencies, including our python3-saml
  fork and extra's for local development
* Documented some security aspects that you need to get right when deploying your
  project.
* Refactored test setup to be more pytest oriented
* Code refactors
* Removed the base metadata generation methods and generic management command. The
  explicit commands and Saml2 client subclasses replace this (the original stuff was
  unused).
* Refactored management commands
* Added ``--save-config`` flag to management commands to support CLI-driven configuration
  and persisting that config to the database.

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
