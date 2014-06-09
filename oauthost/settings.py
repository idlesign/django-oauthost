from django.conf import settings

from .auth_handlers import BearerAuthHandler


# Someday here might be something more than bare Bearer.
TOKEN_TYPE_BEARER = 'bearer'
REGISTRY_TOKEN_TYPE = {
    (TOKEN_TYPE_BEARER, 'Bearer', BearerAuthHandler),
}

TEMPLATE_AUTHORIZE = getattr(settings, 'OAUTHOST_TEMPLATE_AUTHORIZE', 'oauthost/authorize.html')
TEMPLATE_AUTHORIZE_ERROR = getattr(settings, 'OAUTHOST_TEMPLATE_AUTHORIZE_ERROR', 'oauthost/authorize_error.html')
TEMPLATE_AUTHORIZE_PROCEED = getattr(settings, 'OAUTHOST_TEMPLATE_AUTHORIZE_PROCEED', 'oauthost/authorize_proceed.html')
TEMPLATE_FORBIDDEN = getattr(settings, 'OAUTHOST_TEMPLATE_FORBIDDEN', 'oauthost/forbidden.html')
TEMPLATE_RESTRICTED = getattr(settings, 'OAUTHOST_TEMPLATE_RESTRICTED', 'oauthost/restricted.html')
