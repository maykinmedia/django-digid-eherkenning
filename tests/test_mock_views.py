from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, modify_settings, override_settings
from django.urls import reverse, reverse_lazy

from furl import furl

from digid_eherkenning.mock.conf import (
    ImproperlyConfigured,
    should_validate_idp_callback_urls,
)


class DigidMockTestCase(TestCase):
    def assertNoDigidURLS(self, response):
        # verify no links to DigiD remain in template
        self.assertNotContains(response, "://digid.nl")
        self.assertNotContains(response, "://www.digid.nl")


OVERRIDE_SETTINGS = dict(
    DIGID_MOCK_APP_TITLE="FooBarBazz-MockApp",
    DIGID_MOCK_RETURN_URL=reverse_lazy(
        "test-success"
    ),  # url to redirect to after success
    DIGID_MOCK_CANCEL_URL=reverse_lazy(
        "test-index"
    ),  # url to navigate to when users clicks 'cancel/annuleren'
    ROOT_URLCONF="tests.project.mock_urls",
)

MODIFY_SETTINGS = dict(
    AUTHENTICATION_BACKENDS={
        "append": [
            "digid_eherkenning.mock.backends.DigiDBackend",
        ],
        "remove": [
            "digid_eherkenning.backends.DigiDBackend",
        ],
    }
)


@override_settings(**OVERRIDE_SETTINGS)
@modify_settings(**MODIFY_SETTINGS)
class TestAppIndexTests(TestCase):
    def test_get_returns_valid_response(self):
        url = reverse("test-index")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("digid:login"))


@override_settings(**OVERRIDE_SETTINGS)
@modify_settings(**MODIFY_SETTINGS)
class LoginViewTests(DigidMockTestCase):
    def test_get_returns_http400_on_missing_params(self):
        url = reverse("digid-mock:login")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 400)

    def test_get_returns_valid_response(self):
        url = reverse("digid-mock:login")
        data = {
            "acs": reverse("digid:acs"),
            "next": reverse("test-success"),
            "cancel": reverse("test-index"),
        }
        response = self.client.get(url, data=data)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "FooBarBazz-MockApp")
        self.assertContains(response, reverse("digid-mock:password"))
        self.assertNoDigidURLS(response)

    @override_settings(DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS=True)
    def test_cancel_url_cannot_have_different_host(self):
        url = reverse("digid-mock:login")
        data = {
            "acs": reverse("digid:acs"),
            "next": reverse("test-success"),
            "cancel": "http://some-other-testserver" + reverse("test-index"),
        }
        response = self.client.get(url, data=data)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"'cancel_url' parameter must be a safe url")

        with override_settings(DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS=False):
            response = self.client.get(url, data=data)
            self.assertEqual(response.status_code, 200)

    @override_settings(DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS=True)
    def test_next_url_cannot_have_different_host(self):
        url = reverse("digid-mock:login")
        data = {
            "acs": reverse("digid:acs"),
            "next": "http://some-other-testserver" + reverse("test-success"),
            "cancel": reverse("test-index"),
        }
        response = self.client.get(url, data=data)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"'next_url' parameter must be a safe url")

        with override_settings(DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS=False):
            response = self.client.get(url, data=data)
            self.assertEqual(response.status_code, 200)

    @override_settings(DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS=True)
    def test_next_and_cancel_url_can_be_relative(self):
        url = reverse("digid-mock:login")
        data = {
            "acs": reverse("digid:acs"),
            "next": reverse("test-success"),
            "cancel": reverse("test-index"),
        }
        response = self.client.get(url, data=data)
        self.assertEqual(response.status_code, 200)

    @override_settings(DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS=True)
    def test_next_and_cancel_url_must_be_secure_if_idp_is_secure(self):
        url = reverse("digid-mock:login")
        data = {
            "acs": reverse("digid:acs"),
            "next": "http://testserver" + reverse("test-success"),
            "cancel": "http://testserver" + reverse("test-index"),
        }
        response = self.client.get(url, data=data, secure=True)
        self.assertEqual(response.status_code, 400)

        response = self.client.get(url, data=data, secure=False)
        self.assertEqual(response.status_code, 200)

    @override_settings(DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS="True")
    def test_conf_setting_must_be_a_bool(self):
        with self.assertRaises(ImproperlyConfigured):
            should_validate_idp_callback_urls()

    @override_settings()
    def test_conf_setting_defaults_to_inverse_of_debug_flag(self):
        del settings.DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS

        with override_settings(DEBUG=False):
            self.assertTrue(should_validate_idp_callback_urls())

        with override_settings(DEBUG=True):
            self.assertFalse(should_validate_idp_callback_urls())


@override_settings(**OVERRIDE_SETTINGS)
@modify_settings(**MODIFY_SETTINGS)
class PasswordLoginViewTests(DigidMockTestCase):
    def test_get_returns_http400_on_missing_params(self):
        url = reverse("digid-mock:password")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 400)

    def test_get_returns_valid_response(self):
        url = reverse("digid-mock:password")
        data = {
            "acs": reverse("digid:acs"),
            "next": reverse("test-success"),
            "cancel": reverse("test-index"),
        }
        response = self.client.get(url, data=data)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "FooBarBazz-MockApp")
        self.assertContains(response, reverse("digid-mock:login"))
        self.assertNoDigidURLS(response)

    def test_post_redirects_and_authenticates(self):
        url = reverse("digid-mock:password")
        params = {
            "acs": reverse("digid:acs"),
            "next": reverse("test-success"),
            "cancel": reverse("test-index"),
        }
        url = f"{url}?{urlencode(params)}"

        data = {
            "auth_name": "296648875",
            "auth_pass": "bar",
        }
        # post our password to the IDP
        response = self.client.post(url, data, follow=False)

        # it will redirect to our ACS
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("digid:acs"), response["Location"])

        # follow the ACS redirect and get/create the user
        response = self.client.get(response["Location"], follow=False)

        User = get_user_model()
        user = User.digid_objects.get(bsn="296648875")

        # follow redirect to 'next'
        self.assertRedirects(response, reverse("test-success"))

        response = self.client.get(response["Location"], follow=False)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Je bent ingelogged als gebruiker")
        self.assertContains(response, "<code>{}</code>".format(str(user)))
        self.assertContains(response, "<code>296648875</code>")

    def test_post_redirect_retains_acs_querystring_params(self):
        url = reverse("digid-mock:password")
        params = {
            "acs": f"{reverse('digid:acs')}?foo=bar",
            "next": reverse("test-success"),
            "cancel": reverse("test-index"),
        }
        url = f"{url}?{urlencode(params)}"

        data = {
            "auth_name": "296648875",
            "auth_pass": "bar",
        }
        # post our password to the IDP
        response = self.client.post(url, data, follow=False)

        # it will redirect to our ACS
        expected_redirect = furl(reverse("digid:acs")).set(
            {
                "foo": "bar",
                "bsn": "296648875",
                "next": reverse("test-success"),
            }
        )
        self.assertRedirects(
            response, str(expected_redirect), fetch_redirect_response=False
        )


@override_settings(**OVERRIDE_SETTINGS)
@modify_settings(**MODIFY_SETTINGS)
class LogoutViewTests(TestCase):
    def test_logout(self):
        User = get_user_model()
        user = User.objects.create_user(username="testuser", password="test")
        self.client.force_login(user)

        url = reverse("digid:logout")
        response = self.client.post(url)

        self.assertEqual(response.status_code, 302)
        self.assertFalse("_auth_user_id" in self.client.session)
