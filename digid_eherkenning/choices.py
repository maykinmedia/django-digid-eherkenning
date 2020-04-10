from djchoices import ChoiceItem, DjangoChoices


class SectorType(DjangoChoices):
    bsn = ChoiceItem("s00000000", "BSN")
    sofi = ChoiceItem("s00000001", "SOFI")
