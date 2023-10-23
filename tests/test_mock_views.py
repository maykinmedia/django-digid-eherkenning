from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.test import TestCase, modify_settings, override_settings
from django.urls import reverse, reverse_lazy

from furl import furl


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
        response = self.client.get(url)

        self.assertEqual(response.status_code, 302)
        self.assertFalse("_auth_user_id" in self.client.session)
