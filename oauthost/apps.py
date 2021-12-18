from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _


class OauthostConfig(AppConfig):
    """Oauthost configuration."""

    name = 'oauthost'
    verbose_name = _('OAuthost')
