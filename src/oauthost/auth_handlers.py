from django.contrib.auth import login
from django.template import loader, RequestContext
from django.http import HttpResponse, HttpRequest
from django.utils.translation import gettext_lazy as _


class BearerAuthHandler:
    """Handles Bearer token authentication calls.

    SPEC: http://tools.ietf.org/html/rfc6750

    """

    _token: str = None
    _request: HttpRequest = None
    _response: HttpResponse = None
    _error: str = None
    _scope: str = None

    def __init__(self, request: HttpRequest, scope):
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

    def validate_token(self) -> bool:

        if self._token is None:
            return False

        from oauthost.models import Token

        token, error = Token.validate_access_token(self._token, self._scope)

        if token is None:
            self._error = error
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
            additional_params = ','.join([f'{key}="{val}"' for key, val in additional_params.items()])

            context = RequestContext(self._request)

            self._response = HttpResponse(
                content=loader.render_to_string(
                    TEMPLATE_RESTRICTED, {'oauthost_title': _('Access Restricted')}, context
                ),
                status=current_error[0]
            )
            self._response['WWW-Authenticate'] = f'Bearer {additional_params}'

    def response(self) -> HttpResponse:
        return self._response
