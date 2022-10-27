import logging
from typing import Callable, Type

from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.http.response import HttpResponseBase
from django.utils.translation import gettext as _
from django.views import View

from ..models.metadata_config import BaseConfiguration

logger = logging.getLogger(__name__)


class MetadataView(View):
    config_model: Type[BaseConfiguration] = BaseConfiguration
    metadata_generator: Callable[[], bytes] = lambda: b""

    def get(self, request: HttpRequest) -> HttpResponseBase:
        config = self.config_model.get_solo()

        try:
            config.clean()
        except ValidationError as error:
            logger.warning(
                "Invalid '%s' configuration",
                self.config_model._meta.verbose_name,
                exc_info=error,
            )
            error_message = _(
                "Something went wrong while generating the metadata. Please get in touch "
                "with your technical contact person and inform them the configuration is "
                "invalid."
            )
            return HttpResponseBadRequest(error_message)

        metadata = self.metadata_generator()
        return HttpResponse(metadata, content_type="text/xml")
