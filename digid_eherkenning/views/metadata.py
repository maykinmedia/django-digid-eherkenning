import logging
from typing import Callable, Type

from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.http.response import HttpResponseBase
from django.utils.translation import gettext as _
from django.views import View

from ..models.base import BaseConfiguration

logger = logging.getLogger(__name__)


class MetadataView(View):
    config_model: Type[BaseConfiguration] = BaseConfiguration
    metadata_generator: Callable[[], bytes] = lambda: b""
    filename: str = "metadata.xml"

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
            return self._get_generic_error_response()

        try:
            metadata = self.metadata_generator()
        except Exception as error:
            logger.warning(
                "Failed generating metadata for '%s' at '%s'",
                self.config_model._meta.verbose_name,
                request.path,
                exc_info=error,
                extra={
                    "request": request,
                    "config_model": self.config_model,
                },
            )
            return self._get_generic_error_response()
        # RFC 6266, 4.1, and RFC 2616 Section 2.2
        sanitized_filename = self.filename.replace('"', r"\"")
        return HttpResponse(
            metadata,
            content_type="text/xml",
            headers={
                "Content-Disposition": f'attachment; filename="{sanitized_filename}"',
            },
        )

    @staticmethod
    def _get_generic_error_response() -> HttpResponseBadRequest:
        error_message = _(
            "Something went wrong while generating the metadata. Please get in touch "
            "with your technical contact person and inform them the configuration is "
            "invalid."
        )
        return HttpResponseBadRequest(error_message, content_type="text/plain")
