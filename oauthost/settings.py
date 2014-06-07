import logging

from django.conf import settings
from django.utils.translation import ugettext_lazy as _

from .auth_handlers import BearerAuthHandler

LOGGER = logging.getLogger('django.oauthost')

REGISTRY_EP_AUTH_RESPONSE_TYPE = ['code', 'token']
REGISTRY_EP_TOKEN_GRANT_TYPE = ['authorization_code', 'password', 'client_credentials', 'refresh_token']

# Someday here might be something more than bare Bearer.
TOKEN_TYPE_BEARER = 'bearer'
REGISTRY_TOKEN_TYPE = {
    (TOKEN_TYPE_BEARER, 'Bearer', BearerAuthHandler),
}

AUTH_ENABLED = getattr(settings, 'OAUTHOST_AUTH_ENABLED', True)
TEMPLATE_AUTHORIZE = getattr(settings, 'OAUTHOST_TEMPLATE_AUTHORIZE', 'oauthost/authorize.html')
TEMPLATE_AUTHORIZE_ERROR = getattr(settings, 'OAUTHOST_TEMPLATE_AUTHORIZE_ERROR', 'oauthost/authorize_error.html')
TEMPLATE_AUTHORIZE_PROCEED = getattr(settings, 'OAUTHOST_TEMPLATE_AUTHORIZE_PROCEED', 'oauthost/authorize_proceed.html')
TEMPLATE_FORBIDDEN = getattr(settings, 'OAUTHOST_TEMPLATE_FORBIDDEN', 'oauthost/forbidden.html')
TEMPLATE_RESTRICTED = getattr(settings, 'OAUTHOST_TEMPLATE_RESTRICTED', 'oauthost/restricted.html')

try:
    from siteprefs.toolbox import patch_locals, register_prefs, pref

    patch_locals()
    register_prefs(
        pref(AUTH_ENABLED, verbose_name=_('OAuth 2.0 authorization enabled'), static=False),
    )

except ImportError:
    pass
