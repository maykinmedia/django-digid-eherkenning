"""
Django settings for test project.

Generated by 'django-admin startproject' using Django 3.0.5.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import os
from django.urls import reverse_lazy

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "lcs06!#jz)21hm6)74bs4o@&829z#z6s&)&rlik*q78m^ltbdk"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "digid_eherkenning",
    "tests.project",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "tests.project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "tests.project.wsgi.application"


# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(BASE_DIR, "db.sqlite3"),
    }
}


# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",},
]


# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = "/static/"

#
# DigiD settings
#
DIGID = {
    "base_url": "https://sp.example.nl",
    "entity_id": "sp.example.nl/digid",
    "metadata_file": os.path.join(BASE_DIR, "files", "digid", "metadata"),
    "key_file": os.path.join(BASE_DIR, "files", "snakeoil-cert/ssl-cert-snakeoil.key"),
    "cert_file": os.path.join(BASE_DIR, "files", "snakeoil-cert/ssl-cert-snakeoil.pem"),
    "service_entity_id": "https://was-preprod1.digid.nl/saml/idp/metadata",
    "attribute_consuming_service_index": "1",
    "service_name": "Example",
    "requested_attributes": [],
    "login_url": reverse_lazy('admin:login'),
}

#
# eHerkenning settings
#

EHERKENNING = {
    "oin": "00000000000000000000",
    "organisation_name": "Example",
    "service_uuid": "",
    "service_name": "Example",
    "service_loa": "urn:etoegang:core:assurance-class:loa3",
    "service_index": "1",
    "service_instance_uuid": "",
    "service_url": "",
    "privacy_policy_url": "",
    "herkenningsmakelaars_id": "00000000000000000000",
    "key_file": os.path.join(BASE_DIR, "files", "snakeoil-cert/ssl-cert-snakeoil.key"),
    "cert_file": os.path.join(BASE_DIR, "files", "snakeoil-cert/ssl-cert-snakeoil.pem"),
    # Also used as entity ID
    "base_url": "https://example.com",
    "metadata_file": os.path.join(BASE_DIR, "files", "eherkenning", "metadata"),
    "service_entity_id": "urn:etoegang:HM:00000003520354760000:entities:9632",
    "entity_id": "urn:etoegang:DV:0000000000000000001:entities:0002",
    "attribute_consuming_service_index": "1",
    "requested_attributes": [],
    "login_url": reverse_lazy('admin:login'),
}


AUTHENTICATION_BACKENDS = [
    "digid_eherkenning.backends.DigiDBackend",
    "digid_eherkenning.backends.eHerkenningBackend",
]

AUTH_USER_MODEL = "project.User"
