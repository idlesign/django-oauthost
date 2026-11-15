from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class OauthostConfig(AppConfig):
    """Oauthost configuration."""

    name = 'oauthost'
    verbose_name = _('OAuthost')
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        super().ready()

        from django.conf import settings

        # Register OpenAPI authentication scheme when drf-spectacular is in use.
        if 'drf_spectacular' in settings.INSTALLED_APPS:
            from .integration import drf_spectacular  # noqa: F401
