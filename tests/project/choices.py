from django.db import models

class UserLoginType(models.TextChoices):
    digid = "digid", "DigiD"
    eherkenning = "eherkenning", "eHerkenning"
