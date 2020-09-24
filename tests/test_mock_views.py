from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings, modify_settings
from django.urls import reverse, reverse_lazy


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
            "auth_name": "123456789",
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
        user = User.digid_objects.get(bsn="123456789")

        # follow redirect to 'next'
        self.assertRedirects(response, reverse("test-success"))

        response = self.client.get(response["Location"], follow=False)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Je bent ingelogged als gebruiker")
        self.assertContains(response, "<code>{}</code>".format(str(user)))
        self.assertContains(response, "<code>123456789</code>")

    def test_backend_rejects_non_numerical_name(self):
        url = reverse("digid-mock:password")
        params = {
            "acs": reverse("digid:acs"),
            "next": reverse("test-success"),
            "cancel": reverse("test-index"),
        }
        url = f"{url}?{urlencode(params)}"

        data = {
            "auth_name": "foo",
            "auth_pass": "bar",
        }
        # post our password to the IDP
        response = self.client.post(url, data, follow=False)

        # it will redirect to our ACS
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("digid:acs"), response["Location"])

        # follow the ACS redirect and get/create the user
        response = self.client.get(response["Location"], follow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("test-index"), response["Location"])

        User = get_user_model()
        with self.assertRaises(User.DoesNotExist):
            User.digid_objects.get(bsn="foo")
