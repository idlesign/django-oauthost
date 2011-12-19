import logging

from oauthost.auth_handlers import BearerAuthHandler

LOGGER = logging.getLogger('django.oauthost')

REGISTRY_EP_AUTH_RESPONSE_TYPE = ['code', 'token']
REGISTRY_EP_TOKEN_GRANT_TYPE = ['authorization_code', 'password', 'client_credentials', 'refresh_token']

# Someday here might be something more than bare Bearer.
TOKEN_TYPE_BEARER = 'bearer'
REGISTRY_TOKEN_TYPE = {
    (TOKEN_TYPE_BEARER, 'Bearer', BearerAuthHandler),
}

OAUTHOST_TEMPLATE_AUTHORIZE = 'oauthost/authorize.html'
OAUTHOST_TEMPLATE_AUTHORIZE_ERROR = 'oauthost/authorize_error.html'
OAUTHOST_TEMPLATE_AUTHORIZE_PROCEED = 'oauthost/authorize_proceed.html'
OAUTHOST_TEMPLATE_FORBIDDEN = 'oauthost/forbidden.html'
OAUTHOST_TEMPLATE_RESTRICTED = 'oauthost/restricted.html'
