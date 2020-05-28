from djchoices import ChoiceItem, DjangoChoices


class UserLoginType(DjangoChoices):
    digid = ChoiceItem("digid", "DigiD")
    eherkenning = ChoiceItem("eherkenning", "eHerkenning")
