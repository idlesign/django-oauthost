import logging

from django.utils.translation import ugettext_lazy as _

LOGGER = logging.getLogger('django.oauthost')

REGISTRY_EP_AUTH_RESPONSE_TYPE = ['code', 'token']
REGISTRY_EP_TOKEN_GRANT_TYPE = ['authorization_code', 'password', 'client_credentials', 'refresh_token']

TOKEN_TYPE_BEARER = 'bearer'
REGISTRY_TOKEN_TYPE = {
    (TOKEN_TYPE_BEARER, _('Bearer')),
}

OAUTHOST_TEMPLATE_AUTHORIZE = 'oauthost/authorize.html'
OAUTHOST_TEMPLATE_AUTHORIZE_ERROR = 'oauthost/authorize_error.html'
OAUTHOST_TEMPLATE_AUTHORIZE_PROCEED = 'oauthost/authorize_proceed.html'
OAUTHOST_TEMPLATE_FORBIDDEN = 'oauthost/forbidden.html'
