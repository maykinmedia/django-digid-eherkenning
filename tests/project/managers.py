from digid_eherkenning.managers import BaseDigidManager, BaseeHerkenningManager

from .choices import UserLoginType


class DigidManager(BaseDigidManager):
    def get_queryset(self):
        return super().get_queryset().filter(login_type=UserLoginType.digid)

    def get_by_bsn(self, bsn):
        return self.get_queryset().get(bsn=bsn)

    def digid_create(self, bsn, **kwargs):
        return super().create(
            username=f"user-{bsn}",
            login_type=UserLoginType.digid,
            bsn=bsn,
        )


class eHerkenningManager(BaseeHerkenningManager):
    def get_queryset(self):
        return super().get_queryset().filter(login_type=UserLoginType.eherkenning)

    def get_by_rsin(self, rsin):
        return self.get_queryset().get(rsin=rsin)

    def eherkenning_create(self, rsin, **kwargs):
        return super().create(
            username=f"user-{rsin}",
            login_type=UserLoginType.eherkenning,
            rsin=rsin,
        )
