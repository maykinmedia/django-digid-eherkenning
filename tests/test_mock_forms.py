import pytest

from digid_eherkenning.mock.idp.forms import BsnLoginTextInputForm


@pytest.mark.parametrize(
    "auth_bsn, bsn_has_error",
    [
        ("296648875", False),  # OK
        ("abcdefghe", True),  # bsn wrong type
        ("2966488759", True),  # bsn too long
        ("29664887", True),  # bsn too short
        ("123456789", True),  # bsn wrong checksum
    ],
)
def test_bsn_login_form_validate(auth_bsn, bsn_has_error):
    form = BsnLoginTextInputForm(data={"auth_bsn": auth_bsn})

    assert form.has_error("auth_bsn") is bsn_has_error
    assert form.is_valid() is not bsn_has_error
