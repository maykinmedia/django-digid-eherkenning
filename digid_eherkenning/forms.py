from django import forms


class SAML2Form(forms.Form):
    SAMLRequest = forms.CharField()
    RelayState = forms.CharField(max_length=80)
