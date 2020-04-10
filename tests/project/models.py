from django.contrib.auth.models import AbstractUser
from django.db import models

from .choices import UserLoginType
from .managers import DigidManager


class User(AbstractUser):
    login_type = models.CharField(
        max_length=20,
        choices=UserLoginType.choices,
        validators=[UserLoginType.validator,],
    )
    bsn = models.CharField(max_length=9)

    digid_objects = DigidManager()
