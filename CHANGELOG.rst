=========
Changelog
=========

0.20.0 (2025-03-13)
===================

**💥⚠️ Breaking changes**

* Data migrations were removed. If you still need them make sure you upgrade to v0.19
  first.

**Other changes**

* Squashed the migrations - new installs now use optimized migrations.
* Fixed running ``tox`` locally.
* eHerkenning service catalog generation now takes the next certificate into account if
  one is available.
* Pinned the support ``xmlsec`` version to 1.3.14 due to build errors in combination
  with ``lxml``. We expect this to be resolved upstream soon-ish.

0.19.2 (2025-01-09)
===================

Very small patch release.

* The default value for DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS is no longer equal to
  settings.DEBUG but to its inverse.

0.19.1 (2025-01-08)
===================

Small patch release.

* Fixed new-migration check because of outdated help text.
* Added the option to validate redirect URIs in the DigiD mock, mostly to avoid
  unproductive discussions with auditors.

0.19.0 (2025-01-08)
===================

Added some additional eHerkenning/eIDAS metadata fields.

* Added fields for administrative contact person details.
* Added a field for a separate eIDAS service description.

0.18.0 (2024-12-27)
===================

Metadata-generation tweaks.

It was reported to Open Formulieren that the generated (eHerkenning) metadata is not
according to spec. This has been resolved in this release. No runtime authentication
behaviour should be changed.

* Updated the XSD for service catalog to v1.24.
* Removed the default requested attributes from eHerkenning config model.
* eHerkenning metadata tests now perform SAML v2.0 XSD validation.
* Removed the forbidden NameIDFormat element from the eHerkenning metadata.
* If both eHerkenning and eIDAS assertion consumer services are included, the
  eHerkenning service is marked as default.
* Removed the SHA1 signing/digest algorithms from the available options for eHerkenning.
* Removed the ``use`` attribute from  the key descriptors in the eHerkenning metadata,
  marking each key as used for both encryption and signing.

0.17.2 (2024-07-26)
===================

Bugfix release

* Fixed invalid key/certificate pairs not being skipped in the certificate selection
  process.

0.17.1 (2024-07-25)
===================

Small bugfix to make sure ``CertificateProblem`` can be pickled.

0.17.0 (2024-07-24)
===================

**💥⚠️ Breaking changes**

* Removed the ``generate_digid_metadata``, ``generate_eherkenning_metadata`` and
  ``generate_eherkenning_dienstcatalogus`` management commands. This metadata is
  available through the admin interface and existing URLs/views.

**Features**

* [#75] The metadata XML pages now force the download of the XML file rather than
  letting the browser display it.
* [#74] Added support for "future" SAML certificates. When your current signing
  certificate is close to expiry, you can prepare the new certificate and generate +
  exchange the new metadata with the identity provider for a seamless transition once
  the old certificate expires.

**Other changes**

* Support for encrypted private keys is moved to the certificate management
  application. You can enter the passphrase there instead of in the DigiD/eHerkenning
  configuration forms.

0.16.0 (2024-07-02)
===================

Small iteration on OIDC integration.

* Removed the ``oidc_exempt_urls`` fields from the configuration models, following the
  change in ``mozilla-django-oidc-db``.

0.15.0 (2024-06-24)
===================

Further iteration on the OIDC integration.

* 💥⚠️ Renamed the ``OpenIDConnectBaseConfig`` base model to ``BaseConfig``
* Added "level of assurance" claim configuration
* Added ability to specify a fallback LOA value
* Added ability to map claim values to their standard values
* Added ``digid_eherkenning.oidc.claims.process_claims`` helper to normalize received
  claims from the OIDC provider for further processing. See the tests for the intended
  behaviour.
* Added Dutch translations.

0.14.0 (2024-06-13)
===================

Feature and Maintenance release

**💥⚠️ Breaking changes**

* Dropped support for Django versions older than 4.2 (LTS).
* Dropped support for Python versions older than 3.10.

**Features**

* Added optional dependency group for OIDC support. Install with
  ``django-digid-eherkenning[oidc]``.
* Ported Open Forms' ``digid_eherkenning_oidc_generics`` into the
  ``digid_eherkenning.oidc`` sub-package, which is opt-in.
* Extended OpenID Connect configuration models to be able to capture all relevant
  authentication context data.

The OpenID Connect features are currently considered to be in "preview" mode until we've
battle-tested them in Open Forms and Open Inwoner.

0.13.1 (2024-04-08)
===================

* [#67] Fixed admin crash due to split up EH/eIDAS LOA fields.

0.13.0 (2024-03-29)
===================

* [#58] Do not replace the entityID for eHerkenning with a URL when it should be a URN (happened when parsing metadata).
* [open-formulieren/open-forms#3950] Improved the eHerkenning service catalogue to be compatible with Signicat.
* [open-formulieren/open-forms#3950] Make eIDAS and eHerkenning LoA configuration independent of each other.
* [open-formulieren/open-forms#3969] Remove support for overriding the LoA in the Authentication Request for eHerkenning and eIDAS.

0.12.0 (2024-02-23)
===================

Maintenance release

Note that older versions of django-digid-eherkenning have an upper bound of
``maykin-python3-saml==1.16.0.post1`` due to the implicit PyOpenSSL dependency. If you
upgrade maykin-python3-saml, you also need to update to
``django-digid-eherkenning>=0.12.0``.

* Dropped the (implicit) dependency on PyOpenSSL. Now the cryptography package is used
  directly.
* Made the cryptography dependency explicit.

0.11.0 (2024-02-15)
===================

Maintenance and bugfix release

There are no expected breaking/backwards changes, but we did publish a new version of
maykin-python3-saml which has changed build/project tooling. We recommend properly
testing this flow on test/staging environments.

* Fixed the documentation build
* Updated deprecated CI actions
* Addressed build failures with lmxl 5+
* Replaced deprecated defusedxml.lxml module usage
* Removed explicit defusedxml dependency
* Fixed the handling of metadata incorrectly assumed to be string rather than bytes
* Pin lxml 4.7.1 lower bound
* Pin maykin-python3-saml lower bound (which removes the defusedxml dependency)

0.10.0 (2023-12-05)
===================

Introduced a small behaviour change

Before, when returning from the DigiD/eHerkenning login flow and consuming the SAML
artifact (in the assertion consumer service), we checked whether the IP address of the
client was still the same IP address that initiated the authentication context. From
error monitoring, it was clear this leads to false positives, so the fatal error has now
been relaxed to a warning.

0.9.0 (2023-10-23)
==================

Quality of life update

* [#45] Added automatic metadata retrieval

    * You can now configure a metadata source URL, which will download and process the
      metadata automatically.
    * Added a management command ``update_stored_metadata`` to refetch the metadata and
      process any updates.

* Added BSN validation to mock login form.

0.8.2 (2023-09-01)
==================

Nothing functional. Changed the verbose names of

* eHerkenning service *instance* UUID
* eIDAS service *instance* UUID


0.8.1 (2023-08-15)
==================

* Made EHerkenningConfiguration.loa required
  It was previously possible to accidentally misconfigure by selecting the
  empty option for the LOA in the admin.

  This patch contains a migration that will set undefined eHerkennning LOAs to
  low_plus. But if you have an invalid LOA set, the migration will fail with
  an IntegrityError. In case this happens, go to the admin and select a LOA.


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
