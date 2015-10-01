from datetime import datetime

from django.contrib.auth import login
from django.core.exceptions import ObjectDoesNotExist
from django.template import loader, RequestContext
from django.http import HttpResponse
from django.utils.translation import ugettext_lazy as _


class BearerAuthHandler(object):
    """Handles Bearer token authentication calls.

    SPEC: http://tools.ietf.org/html/rfc6750

    """

    _token = None
    _request = None
    _response = None
    _error = None
    _scope = None

    def __init__(self, request, scope):
        self._request = request
        self._scope = scope

        self.fetch_token()
        self.validate_token()
        self.prepare_response()

    def fetch_token(self):
        token = None

        request = self._request

        # Authorization Request Header Field
        authorization_method = request.META.get('HTTP_AUTHORIZATION')
        if authorization_method is not None:
            auth_method_type, auth_method_value = authorization_method.split(' ', 1)
            if auth_method_type == 'Bearer':
                token = auth_method_value
        else:
            # Form-Encoded Body Parameter or URI Query Parameter
            token = request.POST.get('access_token', request.GET.get('access_token'))

        if token is None:
            self._error = 'invalid_request'
        else:
            self._token = token

    def validate_token(self):

        if self._token is None:
            return False

        from oauthost.models import Token
        try:
            token = Token.objects.get(access_token=self._token)
        except ObjectDoesNotExist:
            self._error = 'invalid_token'
            return False

        # If token found is granted to all the different token type.
        if token.access_token_type != 'bearer':
            self._error = 'invalid_token'
            return False

        # Token has expired.
        if token.expires_at is not None and token.expires_at <= datetime.now():
            self._error = 'invalid_token'
            return False

        # If target scope is defined, let's verify that the token has access to it.
        if self._scope is not None:
            if not token.scopes.filter(identifier=self._scope).count():
                self._error = 'insufficient_scope'
                return False

        # Token is valid and now we'll log it's owner in.

        # Manual .backend attribute is set as an alternative to `authenticate()`.
        # For now this hardcoded backend will do.
        token.user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(self._request, token.user)

        return True

    def prepare_response(self):

        if self._error is not None:
            from .settings import TEMPLATE_RESTRICTED

            errors = {
                'invalid_request': (400, 'Request is malformed. Check request parameters validity.'),
                'invalid_token': (401, 'Given access token is invalid'),
                'insufficient_scope': (403, 'Access token grants no access to required scope.')
            }

            current_error = errors[self._error]
            additional_params = {
                'error': self._error, 'error_description': current_error[1]
            }
            additional_params = ',' . join(['%s="%s"' % (i[0], i[1]) for i in additional_params.items()])
            context = RequestContext(self._request)
            self._response = HttpResponse(
                content=loader.render_to_string(
                    TEMPLATE_RESTRICTED, {'oauthost_title': _('Access Restricted')}, context
                ),
                status=current_error[0]
            )
            self._response['WWW-Authenticate'] = 'Bearer %s' % additional_params

    def response(self):
        return self._response