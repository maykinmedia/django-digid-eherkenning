from copy import deepcopy

from django.forms import modelform_factory

from mozilla_django_oidc_db.constants import OIDC_MAPPING
from mozilla_django_oidc_db.forms import OpenIDConnectConfigForm

from .models import OpenIDConnectBaseConfig


def admin_modelform_factory(model: type[OpenIDConnectBaseConfig], *args, **kwargs):
    """
    Factory function to generate a model form class for a given configuration model.

    The configuration model is expected to be a subclass of
    :class:`~digid_eherkenning_oidc_generics.models.OpenIDConnectBaseConfig`.

    Additional args and kwargs are forwarded to django's
    :func:`django.forms.modelform_factory`.
    """
    kwargs.setdefault("form", OpenIDConnectConfigForm)
    Form = modelform_factory(model, *args, **kwargs)

    assert issubclass(
        Form, OpenIDConnectConfigForm
    ), "The base form class must be a subclass of OpenIDConnectConfigForm."

    # update the mapping of discovery endpoint keys to model fields, since our base
    # model adds the ``oidc_op_logout_endpoint`` field.
    Form.oidc_mapping = {
        **deepcopy(OIDC_MAPPING),
        "oidc_op_logout_endpoint": "end_session_endpoint",
    }
    Form.required_endpoints = [
        *Form.required_endpoints,
        "oidc_op_logout_endpoint",
    ]
    return Form
