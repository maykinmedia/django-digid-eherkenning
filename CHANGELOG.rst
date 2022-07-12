=========
Changelog
=========

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
