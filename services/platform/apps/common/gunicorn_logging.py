"""Access logging with bearer URL values removed before interpolation."""

from typing import TYPE_CHECKING, Any, cast

from gunicorn.glogging import Logger

from apps.common.secret_urls import SecretURLFilter, redact_urls

if TYPE_CHECKING:
    from gunicorn.glogging import _AtomsDict


class RedactingLogger(Logger):
    def setup(self, cfg: Any) -> None:
        super().setup(cfg)
        for logger in (self.error_log, self.access_log):
            for handler in logger.handlers:
                handler.addFilter(SecretURLFilter())

    def atoms(self, resp: Any, req: Any, environ: Any, request_time: Any) -> "_AtomsDict":
        return cast("_AtomsDict", redact_urls(super().atoms(resp, req, environ, request_time)))
