import pytest

from digid_eherkenning.mock.idp.forms import PasswordLoginForm


@pytest.mark.parametrize(
    "auth_name, auth_pass, name_has_error, pass_has_error",
    [
        ("296648875", "password", False, False),  # OK
        ("abcdefghe", "password", True, False),  # bsn wrong type
        ("2966488759", "password", True, False),  # bsn too long
        ("29664887", "password", True, False),  # bsn too short
        ("123456789", "password", True, False),  # bsn wrong checksum
        ("296648875", "", False, True),  # missing password
    ],
)
def test_password_login_form_validate(
    auth_name, auth_pass, name_has_error, pass_has_error
):
    form = PasswordLoginForm(data={"auth_name": auth_name, "auth_pass": auth_pass})

    assert form.has_error("auth_name") is name_has_error
    assert form.has_error("auth_pass") is pass_has_error
    assert form.is_valid() is not (name_has_error or pass_has_error)
