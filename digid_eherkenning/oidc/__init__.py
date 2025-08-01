"""
DigiD-eHerkenning-OIDC-generics abstracts authenticating over OIDC.

DigiD/eHerkenning are typically exposed via SAML bindings, but there exist identity
providers that abstract this and instead offer an OpenID Connect flow to log in with
DigiD and/or eHerkenning. This package facilitates integrating with such providers.

The architecture and authentication flows are tricky in some places. Here's an attempt
to explain it.

**Configuration**

Each authentication means (DigiD, eHerkenning, mandate (machtigen) variants...) is
mapped to an OpenID client configuration, which roughly holds:

- the OIDC endpoints to use/redirect users to
- the OAUTH2 client ID and secret to use, which indicate to the IdP which authentication
  means they should send the user to
- which claims to look up/extract from the UserInfo endpoint/JWT

These are stored in (subclasses of) the
:class:`~digid_herkenning.oidc.models.OpenIDConnectBaseConfig` model.

**Authentication flow**

When a user starts a login flow, they:

1. Click the appriopriate button/link
2. A Django view processes this and looks up the relevant configuration
3. The view redirects the user to the identity provider (typically a different domain)
4. Authenticate with the IdP
5. The IdP redirects back to our application
6. Our callback view performs the OIDC exchange and extracts + stores the relevant user
   information
7. Finally, the callback view looks up where the user needs to be redirected to and
   sends them that way.

Steps 2-3 are called the "init" phase in this package, while steps 6-7 are the
"callback" phase.

**Init phase**

The mozilla-django-oidc-db package provides the
:class:`~mozilla_django_oidc_db.views.OIDCInit` view class, for the init phase. It
ensures that the specified config class is persisted in the authentication state.

This package provides concrete views bound to configuration classes:

* :attr:`~digid_herkenning.oidc.views.digid_init`
* :attr:`~digid_herkenning.oidc.views.digid_machtigen_init`
* :attr:`~digid_herkenning.oidc.views.eherkenning_init`
* :attr:`~digid_herkenning.oidc.views.eherkenning_bewindvoering_init`

**Callback phase**

The callback phase validates the code and state, and loads which configuration class
needs to be used from the state. With this information, the authentication backends
from ``settings.AUTHENTICATION_BACKENDS`` are tried in order. Typically this will
use the backend shipped in mozilla-django-oidc-db, or a subclass of it.

The OpenID connect flow exchanges the code for an access token (and ID token), and
the user details are retrieved. You should provide a customized backend to determine
what needs to be done with this user information, e.g. create a django user or store
the information in the django session.
"""
