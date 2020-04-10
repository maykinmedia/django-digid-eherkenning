from digid_eherkenning.managers import BaseDigidManager

from .choices import UserLoginType


class DigidManager(BaseDigidManager):
    def get_queryset(self):
        return super().get_queryset().filter(login_type=UserLoginType.digid)

    def get_by_bsn(self, bsn):
        return self.get_queryset().get(bsn=bsn)

    def digid_create(self, bsn, **kwargs):
        return super().create(
            username="user-{}".format(bsn), login_type=UserLoginType.digid, bsn=bsn,
        )
