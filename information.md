# Background information

## Exmaple metadata file

An example of a metadata file of the digid idp was found at
https://was-preprod1.digid.nl/saml/idp/metadata

## Other SAML2 implementations

A bunch of implementation which use PySAML2. None of them implement the artifact
resolution protocol which we need for eHerkenning/DigiD.

* https://github.com/IronCountySchoolDistrict/django-python3-saml/blob/06d6198ed6c2b9ebfbfe4d6782715d91b6a468d8/django_python3_saml/views.py
* https://github.com/knaperek/djangosaml2/blob/master/djangosaml2/views.py
* https://github.com/fangli/django-saml2-auth/blob/master/django_saml2_auth/urls.py
* https://github.com/OTA-Insight/djangosaml2idp/blob/master/djangosaml2idp/idp.py
* https://github.com/IdentityPython/pysaml2/blob/master/example/sp-wsgi/sp.py
* https://github.com/onelogin/python3-saml

## References

* eHerkenningAttributverstrekking: https://afsprakenstelsel.etoegang.nl/display/as/Attribuutverstrekking
* eHerkenningMetadata: https://afsprakenstelsel.etoegang.nl/display/as/DV+metadata+for+HM
* eHerkenning: https://afsprakenstelsel.etoegang.nl/display/as/Interface+specifications+DV-HM
* eHerkenningDC: https://afsprakenstelsel.etoegang.nl/display/as/Service+catalog
* DigiD: https://www.logius.nl/sites/default/files/public/bestanden/diensten/DigiD/Koppelvlakspecificatie-SAML-DigiD.pdf
* DigiDCheck: logius.nl/sites/default/files/bestanden/website/DigiD Checklist Testen v7.0 (definitief).pdf
* SAML: http://www.oasis-open.org/committees/download.php/56776/sstc-saml-core-errata-2.0-wd-07.pdf
* SAMLBind: https://www.oasis-open.org/committees/download.php/56779/sstc-saml-bindings-errata-2.0-wd-06.pdf
* SAMLProf: https://www.oasis-open.org/committees/download.php/56782/sstc-saml-profiles-errata-2.0-wd-07.pdf
* SAMLMeta: https://www.oasis-open.org/committees/download.php/56785/sstc-saml-metadata-errata-2.0-wd-05.pdf
* XACML: https://docs.oasis-open.org/xacml/2.0/SAML-PROFILE/access_control-xacml-2.0-saml-profile-spec-os.html
