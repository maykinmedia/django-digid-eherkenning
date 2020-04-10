from django.db.models import Manager


class BaseDigidManager(Manager):
    def get_by_bsn(self, bsn):
        raise NotImplementedError

    def digid_create(self, bsn, **kwargs):
        raise NotImplementedError
