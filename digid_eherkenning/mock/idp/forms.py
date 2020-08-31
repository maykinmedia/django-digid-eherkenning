from django import forms
from django.utils.translation import gettext_lazy as _


class PasswordLoginForm(forms.Form):
    auth_name = forms.CharField(max_length=255, required=True, label=_('DigiD gebruikersnaam'))
    auth_pass = forms.CharField(max_length=255, required=True, label=_('Wachtwoord'), widget=forms.PasswordInput)
    remember_login = forms.CharField(label=_('Onthoud mijn DigiD gebruikersnaam'), required=False)
