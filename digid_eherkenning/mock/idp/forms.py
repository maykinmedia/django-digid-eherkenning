from django import forms
from django.utils.translation import gettext_lazy as _

from ...models.digid import MockDigidUser
from ...validators import BSNValidator


class BsnLoginUserModelForm(forms.Form):
    auth_user = forms.ModelChoiceField(
        queryset=MockDigidUser.objects.all(),
        label=_("DigiD mock gebruiker"),
        required=True,
    )

    @property
    def bsn(self):
        return self.cleaned_data["auth_user"].bsn


class BsnLoginTextInputForm(forms.Form):
    auth_bsn = forms.CharField(
        max_length=9,
        label=_("Burgerservicenummer"),
        required=True,
        validators=[BSNValidator()],
    )

    @property
    def bsn(self):
        return self.cleaned_data["auth_bsn"]
