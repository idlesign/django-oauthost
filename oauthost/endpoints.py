import json
from base64 import b64decode
from datetime import datetime
from time import time

from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.utils.translation import ugettext_lazy as _

from .exceptions import EndpointError, OauthostException
from .models import Client, AuthorizationCode, Token, Scope
from .settings import TEMPLATE_AUTHORIZE, TEMPLATE_AUTHORIZE_ERROR, TEMPLATE_AUTHORIZE_PROCEED
from .utils import get_remote_ip, LOGGER

User = get_user_model()


class ScopeException(OauthostException):
    """Exceptions raised if scope conflict occures."""

    def __init__(self, message):
        self.message = message


class ErrorOauthostPage(EndpointError):
    """This error is able to be rendered as oauthost page."""

    def __init__(self, message, request, http_status=400):
        self.request = request
        self.message = message
        self.http_status = http_status

    def as_response(self):
        """For authorization endpoint. Renders a page with error description."""
        data_dict = {'oauthost_title': _('Error'), 'oauthost_error_text': self.message}
        return render(self.request, TEMPLATE_AUTHORIZE_ERROR, data_dict, status=self.http_status)


class ErrorTokenEndpointRedirect(EndpointError):
    """This error is able to perform a redirect from Token Endpoint."""

    def __init__(self, error_type, message, http_status=400, additional_headers=None):
        self.error_type = error_type
        self.message = message
        self.http_status = http_status
        if additional_headers is None:
            additional_headers = {}
        self.additional_headers = additional_headers

    def as_response(self):
        """For token endpoint. Issues JSON error response."""
        return TokenEndpoint.build_response(
            {'error': self.error_type, 'error_description': self.message},
            self.http_status, self.additional_headers
        )


class ErrorAuthorizeEndpointRedirect(EndpointError):
    """This error is able to perform a redirect from Authorize Endpoint."""

    def __init__(self, error_type, message, redirect_uri, state, uri_fragment_supported=False):
        self.error_type = error_type
        self.message = message
        self.redirect_uri = redirect_uri
        self.state = state
        self.uri_fragment_supported = uri_fragment_supported

    def as_response(self):
        """For authorization endpoint. Issues error response."""
        doc = {'error': self.error_type, 'error_description': self.message}
        if self.state is not None:
            doc.update({'state': self.state})
        return HttpResponseRedirect(
            AuthorizeEndpoint.build_redirect_url(self.redirect_uri, doc, self.uri_fragment_supported)
        )


class EndpointBase(object):
    """Basic class for endpoint classes."""

    state = None

    def __init__(self, request):
        self.request = request
        self.input_params = self.filter_input_params(self.get_input_params(request))

    @classmethod
    def get_input_params(cls, request):
        return request.POST

    @classmethod
    def filter_input_params(cls, input_params):
        """Filters request parameters and returns filtered dictionary.

        SPEC: Parameters sent without a value MUST be treated as if they were omitted from the request.

        """
        params_filtered = {}
        for key, value in input_params.items():
            if value:
                params_filtered[key] = value
        return params_filtered

    def filter_scopes(self, client):
        """Gets space delimited list of scopes from client request,
        and returns a list of scope objects, corrected according
        to auth server settings.

        SPEC:

            The authorization server MAY fully or partially ignore the scope
            requested by the client, based on the authorization server policy or
            the resource owner's instructions.  If the issued access token scope
            is different from the one requested by the client, the authorization
            server MUST include the "scope" response parameter to inform the
            client of the actual scope granted.

            If the client omits the scope parameter when requesting
            authorization, the authorization server MUST either process the
            request using a pre-defined default value or fail the request
            indicating an invalid scope.

        """
        scopes_requested = self.input_params.get('scope')  # OPTIONAL

        if scopes_requested is not None:
            # We already have scope objects.
            if isinstance(scopes_requested[0], Scope):
                return scopes_requested
            scopes_requested = scopes_requested.split(' ')
        else:
            scopes_requested = []

        client_scopes = []
        scopes_filtered = []
        scopes_available = []

        # Scopes associated with the client.
        for scope in client.scopes.filter(status=Scope.STATUS_ENABLED).all():
            client_scopes.append(scope)

        # No scopes requested, and client is unrestricted by scopes.
        # Prevent accessing all scopes.
        if not scopes_requested and not client_scopes:
            raise ScopeException('Scope must be provided for this client.')

        if client_scopes:
            scopes_available = client_scopes
        else:
            # Client is not restricted by any scopes, so we make all scopes available.
            for scope in Scope.objects.filter(status=Scope.STATUS_ENABLED).all():
                scopes_available.append(scope)

        if scopes_requested and not scopes_available:
            raise ScopeException('Server doesn\'t accept scope.')

        # Index scopes by ID.
        scopes_available_ = {}
        for scope in scopes_available:
            scopes_available_[scope.identifier] = scope
        scopes_available = scopes_available_
        del scopes_available_

        scopes_available_set = set(scopes_available.keys())
        unsupported = set(scopes_requested).difference(scopes_available_set)
        if unsupported:
            raise ScopeException('Unsupported scope requested: %s.' % ' '.join(unsupported))

        for scope_name in set(scopes_requested).intersection(scopes_available_set):
            scopes_filtered.append(scopes_available[scope_name])

        return scopes_filtered

    @classmethod
    def apply_scopes(cls, auth_obj, filtered_scopes):
        """Link scopes to an auth object: Token or AuthorizationCode."""
        if auth_obj is not None:
            for scope in filtered_scopes:
                auth_obj.scopes.add(scope)

    def check_https(self):
        """Performs an HTTPS check.
        Insecure connections are only available in debug mode.

        """
        if not self.request.is_secure() and not settings.DEBUG:
            raise ErrorOauthostPage(_('OAuth 2.0 requires secure connection.'), self.request, http_status=403)

    def get_response(self):
        """Returns an endpoint response."""
        try:
            self.check_https()
            self.state = self.input_params.get('state')  # OPTIONAL
            response = self.process_request()
        except EndpointError as e:
            return e.as_response()

        return response

    @classmethod
    def generate_token(cls, client, user, token_obj_params=None):
        """Returns an access token."""
        expires_in = client.token_lifetime
        expires_at = None
        if expires_in is not None:
            expires_at = datetime.fromtimestamp(int(time() + expires_in))
        if token_obj_params is None:
            token_obj_params = {}
        return Token(client=client, user=user, expires_at=expires_at, **token_obj_params)

    @classmethod
    def build_token_document(cls, token, expires_in=None, with_refresh_token=True):
        """Returns a token document as a dict."""
        output_params = {
            'access_token': token.access_token,
            'token_type': token.access_token_type
        }

        if token.scopes:
            output_params['scope'] = ' '.join([scope.identifier for scope in token.scopes.all()])

        if expires_in is not None:
            output_params['expires_in'] = expires_in

        if with_refresh_token:
            output_params['refresh_token'] = token.refresh_token

        return output_params

    def get_client(self):
        """Returns client object."""
        raise NotImplementedError()

    def process_request(self):
        """Main method performing client request processing."""
        raise NotImplementedError()


class TokenEndpoint(EndpointBase):
    """
    SPEC:
        The token endpoint is used by the client to obtain an access token by
        presenting its authorization grant or refresh token.  The token
        endpoint is used with every authorization grant except for the
        implicit grant type (since an access token is issued directly).

        Since requests to the token endpoint result in the transmission of
        clear-text credentials (in the HTTP request and response), the
        authorization server MUST require the use of TLS as described in
        Section 1.6 when sending requests to the token endpoint.

        The client MUST use the HTTP "POST" method when making access token
        requests.

        The authorization and token endpoints allow the client to specify the
        scope of the access request using the "scope" request parameter.  In
        turn, the authorization server uses the "scope" response parameter to
        inform the client of the scope of the access token issued.

    PARAMETERS:

        SUCCESS
            access_token REQUIRED
            token_type REQUIRED
            expires_in RECOMMENDED
            refresh_token OPTIONAL
            scope OPTIONAL

        FAILURE
            error REQUIRED
                invalid_request
                invalid_client
                invalid_grant
                unauthorized_client
                unsupported_grant_type
                invalid_scope
            error_description OPTIONAL
            error_uri OPTIONAL

    authorization_code
    ------------------
        REQUEST
            grant_type REQUIRED
            code REQUIRED
            redirect_uri REQUIRED, if the "redirect_uri" was included in the auth request values MUST be identical.
            client_id REQUIRED

    password
    --------
        REQUEST
            grant_type REQUIRED
            username REQUIRED
            password REQUIRED
            scope OPTIONAL

    client_credentials
    ------------------
        REQUEST
            grant_type REQUIRED
            scope OPTIONAL

        SUCCESS
            ** DROP refresh_token

    refresh_token
    -------------
        REQUEST
            grant_type REQUIRED
            refresh_token REQUIRED
            scope OPTIONAL

    """

    ERROR_INVALID_REQUEST = 'invalid_request'
    ERROR_INVALID_CLIENT = 'invalid_client'
    ERROR_INVALID_GRANT = 'invalid_grant'
    ERROR_UNAUTHORIZED_CLIENT = 'unauthorized_client'
    ERROR_UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type'
    ERROR_INVALID_SCOPE = 'invalid_scope'

    _allowed_grant_types = ('authorization_code', 'password', 'client_credentials', 'refresh_token')

    @classmethod
    def build_response(cls, data_dict, http_status=200, additional_headers=None):
        """For token endpoint. Issues JSON response."""
        response = HttpResponse(
            content_type='application/json;charset=UTF-8',
            content=json.dumps(data_dict), status=http_status
        )
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'
        if additional_headers is None:
            additional_headers = {}
        for key, value in additional_headers.items():
            response[key] = value
        return response

    def get_client(self):
        """Returns client object."""
        client = None
        auth_error_headers = {}
        client_id = None
        client_password = None

        authorization_method = self.request.META.get('Authorization')
        if authorization_method is not None:  # Authorization header detected.
            auth_method_type, auth_method_value = authorization_method.split(' ', 1)
            auth_error_headers['WWW-Authenticate'] = auth_method_type
            # Handle client auth through HTTP Basic.
            if auth_method_type == 'Basic':
                try:
                    client_id, client_password = b64decode(auth_method_value).decode('utf-8').split(':')
                except (TypeError, UnicodeDecodeError, AttributeError):
                    pass
        else:

            # SPEC:
            #    Alternatively, the authorization server MAY support including the
            #    client credentials in the request-body using the following
            #    parameters: client_id, client_secret.
            #
            #    Including the client credentials in the request-body using the two
            #    parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
            #    to directly utilize the HTTP Basic authentication scheme (or other
            #    password-based HTTP authentication schemes).  The parameters can only
            #    be transmitted in the request-body and MUST NOT be included in the
            #    request URI.
            #
            #    The parameters can only
            #    be transmitted in the request-body and MUST NOT be included in the
            #    request URI.
            client_id = self.input_params.get('client_id')
            client_password = self.input_params.get('client_secret')

        if client_id is not None:
            try:
                client = Client.objects.get(identifier=client_id)
            except ObjectDoesNotExist:
                client = None

            # SPEC:
            #
            #    A client MAY use the "client_id" request parameter to identify itself
            #    when sending requests to the token endpoint.  In the
            #    "authorization_code" "grant_type" request to the token endpoint, an
            #    unauthenticated client MUST send its "client_id" to prevent itself
            #    from inadvertently accepting a code intended for a client with a
            #    different "client_id".  This protects the client from substitution of
            #    the authentication code.  (It provides no additional security for the
            #    protected resource.)
            if client is not None:
                if client.password.strip() != '' and client.password != client_password:
                    client = None

        if client is None:
            raise ErrorTokenEndpointRedirect(
                self.ERROR_INVALID_CLIENT,
                'Unable to authenticate client by its credentials.',
                http_status=401, additional_headers=auth_error_headers
            )

        return client

    def get_token_for_grant_type(self, grant_type, client):
        """Returns token object for a given grant type."""

        filtered_scopes = []
        if grant_type not in ('refresh_token', 'authorization_code'):  # For refresh we use initially granted scope.
            try:
                filtered_scopes = self.filter_scopes(client)
            except ScopeException as e:
                raise ErrorTokenEndpointRedirect(self.ERROR_INVALID_SCOPE, e.message)

        method = getattr(self, 'handle_%s' % grant_type)
        token = method(client)
        token.save()
        self.apply_scopes(token, filtered_scopes)

        return token

    def handle_authorization_code(self, client):
        """Access Token Request"""

        code = self.input_params.get('code')  # REQUIRED
        redirect_uri = self.input_params.get('redirect_uri')  # REQUIRED

        if code is None or redirect_uri is None:
            raise ErrorTokenEndpointRedirect(
                self.ERROR_INVALID_REQUEST, 'Required param(s) are missing. Expected: `code` and `redirect_uri`.'
            )

        try:
            code = AuthorizationCode.objects.get(code=code)
        except ObjectDoesNotExist:
            raise ErrorTokenEndpointRedirect(self.ERROR_INVALID_GRANT, 'Invalid authorization code is supplied.')

        # SPEC:
        #
        #     If an authorization code is used more than
        #     once, the authorization server MUST deny the request and SHOULD
        #     revoke (when possible) all tokens previously issued based on
        #     that authorization code.  The authorization code is bound to
        #     the client identifier and redirection URI.
        previous_tokens = Token.objects.filter(code=code).all()
        if len(previous_tokens) > 0:
            previous_tokens.delete()
            code.delete()
            raise ErrorTokenEndpointRedirect(
                self.ERROR_INVALID_GRANT, 'Authorization code is used more than once. Code and tokens are revoked.'
            )

        if code.uri != redirect_uri:
            raise ErrorTokenEndpointRedirect(
                self.ERROR_INVALID_GRANT, 'Supplied URI does not match the URI associated with authorization code.'
            )

        if code.client.id != client.id:
            raise ErrorTokenEndpointRedirect(
                self.ERROR_INVALID_GRANT, 'Authorization code supplied was issued to another client.'
            )

        token = self.generate_token(client, code.user, {'code': code})
        token.save()

        # Copying scopes from code.
        for scope in code.scopes.all():
            token.scopes.add(scope)

        return token

    def handle_client_credentials(self, client):
        """
        SPEC:

        Client Credentials Grant

            The client can request an access token using only its client
            credentials (or other supported means of authentication) when the
            client is requesting access to the protected resources under its
            control, or those of another resource owner that have been previously
            arranged with the authorization server (the method of which is beyond
            the scope of this specification).

           The client credentials grant type MUST only be used by confidential
           clients.

        """

        if not client.is_confidential():
            raise ErrorTokenEndpointRedirect(
                'client_credentials', 'This client type is not authorized to use this grant type.'
            )

        # Let's suppose that the user is the one, who has registered the client.
        return self.generate_token(client, client.user)

    def handle_password(self, client):
        """
        SPEC:

        Resource Owner Password Credentials Grant

           The resource owner password credentials grant type is suitable in
           cases where the resource owner has a trust relationship with the
           client, such as the device operating system or a highly privileged
           application.  The authorization server should take special care when
           enabling this grant type and only allow it when other flows are not
           viable.

           This grant type is suitable for clients capable of obtaining the
           resource owner's credentials (username and password, typically using
           an interactive form).  It is also used to migrate existing clients
           using direct authentication schemes such as HTTP Basic or Digest
           authentication to OAuth by converting the stored credentials to an
           access token.

           The authorization server and client SHOULD minimize use of this grant
           type and utilize other grant types whenever possible.

        """
        username = self.input_params.get('username')  # REQUIRED
        password = self.input_params.get('password')  # REQUIRED

        if username is None or password is None:
            raise ErrorTokenEndpointRedirect(
                self.ERROR_INVALID_REQUEST, 'Required param(s) are missing. Expected: `username` and `password`.'
            )

        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                return self.generate_token(client, user)
        except ObjectDoesNotExist:
            pass

        raise ErrorTokenEndpointRedirect(self.ERROR_INVALID_GRANT, 'Supplied resource owner credentials are invalid.')

    def handle_refresh_token(self, client):
        """Refreshes an Access Token."""
        refresh_token = self.input_params.get('refresh_token')

        if refresh_token is None:
            raise ErrorTokenEndpointRedirect(self.ERROR_INVALID_REQUEST, 'Required `refresh_token` param is missing.')

        try:
            token = Token.objects.get(refresh_token=refresh_token)
        except ObjectDoesNotExist:
            raise ErrorTokenEndpointRedirect(self.ERROR_INVALID_GRANT, 'Refresh token supplied is invalid.')
        else:
            if token.client_id != client.id:
                raise ErrorTokenEndpointRedirect(
                    self.ERROR_INVALID_GRANT, 'Refresh token supplied was issued to another client.'
                )

        # For refresh token grant we only swap token values.
        token.date_issued = datetime.now()
        token.access_token = token.generate_token()
        token.refresh_token = token.generate_token()
        return token

    def process_request(self):
        """Main method performing client request processing."""
        grant_type = self.input_params.get('grant_type')  # REQUIRED
        if grant_type not in self._allowed_grant_types:
            raise ErrorTokenEndpointRedirect(self.ERROR_UNSUPPORTED_GRANT_TYPE, 'Unsupported grant type requested')

        client = self.get_client()
        token = self.get_token_for_grant_type(grant_type, client)
        token_doc = self.build_token_document(
            token, client.token_lifetime,
            with_refresh_token=(grant_type != 'client_credentials')
        )

        return self.build_response(token_doc)


class AuthorizeEndpoint(EndpointBase):
    """
    SPEC:
        The authorization endpoint is used to interact with the resource
        owner and obtain an authorization grant.  The authorization server
        MUST first verify the identity of the resource owner.  The way in
        which the authorization server authenticates the resource owner
        (e.g., username and password login, session cookies) is beyond the
        scope of this specification.

        Since requests to the authorization endpoint result in user
        authentication and the transmission of clear-text credentials (in the
        HTTP response), the authorization server MUST require the use of TLS
        as described in Section 1.6 when sending requests to the
        authorization endpoint.

        The authorization server MUST support the use of the HTTP "GET"
        method [RFC2616] for the authorization endpoint and MAY support the
        use of the "POST" method as well.

        The authorization and token endpoints allow the client to specify the
        scope of the access request using the "scope" request parameter.  In
        turn, the authorization server uses the "scope" response parameter to
        inform the client of the scope of the access token issued.

    PARAMETERS:

        REQUEST
            response_type REQUIRED
            client_id REQUIRED
            redirect_uri OPTIONAL
            scope OPTIONAL
            state RECOMMENDED

        FAILURE
            error REQUIRED
                invalid_request
                unauthorized_client
                access_denied
                unsupported_response_type
                invalid_scope
                server_error
                temporarily_unavailable
            error_description OPTIONAL
            error_uri OPTIONAL
            state REQUIRED if set

    code
    ----
        SUCCESS
            code REQUIRED
            state REQUIRED if set

    token
    -----
        SUCCESS
            access_token REQUIRED
            token_type REQUIRED
            expires_in RECOMMENDED
            scope OPTIONAL; if not identical to the scope requested by the client REQUIRED
            state REQUIRED if set

    """

    ERROR_INVALID_REQUEST = 'invalid_request'
    ERROR_UNAUTHORIZED_CLIENT = 'unauthorized_client'
    ERROR_ACCESS_DENIED = 'access_denied'
    ERROR_UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type'
    ERROR_INVALID_SCOPE = 'invalid_scope'
    ERROR_SERVER_ERROR = 'server_error'
    ERROR_TEMPORARILY_UNAVAILABLE = 'temporarily_unavailable'

    _allowed_response_types = ('code', 'token')

    def get_client(self):
        """Returns client object."""
        client_id = self.input_params.get('client_id')  # REQUIRED

        if client_id is None:
            # Fail fast without a DB hit.
            raise ErrorOauthostPage(_('Client ID must be supplied.'), self.request)

        try:
            client = Client.objects.get(identifier=client_id)
        except ObjectDoesNotExist:
            LOGGER.error(
                'Invalid client ID supplied. Value "%s" was sent from IP "%s".', client_id, get_remote_ip(self.request)
            )
            raise ErrorOauthostPage(_('Invalid client ID is supplied.'), self.request)

        return client

    @classmethod
    def get_input_params(cls, request):
        post = request.POST
        return post if post else request.GET

    def get_redirect_url(self, client):
        """Calculates a redirect URI.
        Returns a tuple: uri_from_request, uri_fixed_server

        """
        input_uri = self.input_params.get('redirect_uri')  # OPTIONAL
        actual_uri = input_uri

        registered_uris = [url[0] for url in client.redirection_uris.values_list('uri')]

        # Check redirection URI validity.
        if input_uri is None:
            # redirect_uri is optional and was not supplied.
            if len(registered_uris) == 1:
                # There is only one URI associated with client, so we use it.
                actual_uri = registered_uris[0]
            else:
                # Several URIs are registered with the client, decision is ambiguous.
                LOGGER.error(
                    'Redirect URI was not supplied by client with ID "%s". Request from IP "%s".',
                    client.id, get_remote_ip(self.request)
                )
                raise ErrorOauthostPage(_('Redirect URI should be supplied for a given client.'), self.request)

        # SPEC:
        #
        #     The authorization server SHOULD NOT redirect the user-agent to unregistered or untrusted URIs
        #     to prevent the authorization endpoint from being used as an open redirector.
        if actual_uri not in registered_uris:
            LOGGER.error(
                'An attempt to use an untrusted URI "%s" for client with ID "%s". Request from IP "%s".',
                actual_uri, client.id, get_remote_ip(self.request)
            )
            raise ErrorOauthostPage(_('Redirection URI supplied is not associated with given client.'), self.request)

        return actual_uri

    def render_scopes_page(self, client, scopes):
        """Returns a response with oauthost page listing requested scopes."""
        dict_data = {
            'client': client,
            'scopes_obj': scopes,
            'oauthost_title': _('Authorization Request')
        }
        return render(self.request, TEMPLATE_AUTHORIZE, dict_data)

    def request_auth_confirmation(self):
        client = self.get_client()
        redirect_uri = self.get_redirect_url(client)

        state = self.input_params.get('state')  # RECOMMENDED

        response_type = self.input_params.get('response_type')  # REQUIRED
        if response_type not in self._allowed_response_types:
            raise ErrorAuthorizeEndpointRedirect(
                self.ERROR_UNSUPPORTED_RESPONSE_TYPE, 'Unsupported response type requested', redirect_uri, state
            )

        try:
            filtered_scopes = self.filter_scopes(client)
        except ScopeException as e:
            raise ErrorAuthorizeEndpointRedirect(self.ERROR_INVALID_SCOPE, e.message, redirect_uri, state)

        self.request.session['oauth_client_id'] = client.id
        self.request.session['oauth_response_type'] = response_type
        self.request.session['oauth_redirect_uri'] = redirect_uri
        self.request.session['oauth_scopes_ids'] = [s.id for s in filtered_scopes]
        self.request.session['oauth_state'] = state

        return self.render_scopes_page(client, filtered_scopes)

    def _clear_session(self):
        """For authorization endpoint. Clears oauth data from session."""
        self.request.session[SESSION_KEY] = None

    @classmethod
    def build_redirect_url(cls, redirect_base, params, use_uri_fragment):
        """For authorization endpoint. Builds up redirection URL."""
        if use_uri_fragment:
            redirect_base = '%s#' % redirect_base
        else:
            # SPEC: query component MUST be retained when adding additional query parameters.
            if redirect_base is None or '?' not in redirect_base:
                redirect_base = '%s?' % redirect_base
        return '%s%s' % (redirect_base, '&'.join(['%s=%s' % (key, value) for key, value in params.items()]))

    def get_response_document(self, response_type, redirect_uri, client, params_as_uri_fragment, state):
        """Returns a response object for a given response type."""
        try:
            filtered_scopes = self.filter_scopes(client)
        except ScopeException as e:
            raise ErrorAuthorizeEndpointRedirect(self.ERROR_INVALID_SCOPE, e.message, redirect_uri, state)

        method = getattr(self, 'handle_%s' % response_type)

        output_params = method(client, redirect_uri, filtered_scopes)

        if state is not None:
            output_params['state'] = state

        # SPEC:
        #
        #    Developers should note that some user-agents do not support the
        #    inclusion of a fragment component in the HTTP "Location" response
        #    header field.  Such clients will require using other methods for
        #    redirecting the client than a 3xx redirection response -- for
        #    example, returning an HTML page that includes a 'continue' button
        #    with an action linked to the redirection URI.
        if not client.hash_sign_supported:
            data_dict = {'action_uri': self.build_redirect_url(redirect_uri, output_params, params_as_uri_fragment)}
            return render(self.request, TEMPLATE_AUTHORIZE_PROCEED, data_dict)

        return HttpResponseRedirect(self.build_redirect_url(redirect_uri, output_params, params_as_uri_fragment))

    def handle_code(self, client, redirect_uri, filtered_scopes):
        """
        SPEC:

        Authorization Code Grant

           The authorization code grant type is used to obtain both access
           tokens and refresh tokens and is optimized for confidential clients.
           Since this is a redirection-based flow, the client must be capable of
           interacting with the resource owner's user-agent (typically a web
           browser) and capable of receiving incoming requests (via redirection)
           from the authorization server.

        """
        code = AuthorizationCode(client=client, user=self.request.user, uri=redirect_uri)
        code.save()
        self.apply_scopes(code, filtered_scopes)

        return {'code': code.code}

    def handle_token(self, client, redirect_uri, filtered_scopes):
        """
        SPEC:

        Implicit Grant

            The implicit grant type is used to obtain access tokens (it does not
            support the issuance of refresh tokens) and is optimized for public
            clients known to operate a particular redirection URI.  These clients
            are typically implemented in a browser using a scripting language
            such as JavaScript.

        """
        token = self.generate_token(client, self.request.user)
        token.save()
        self.apply_scopes(token, filtered_scopes)

        return self.build_token_document(token, client.token_lifetime, with_refresh_token=False)

    def process_request(self):
        """Main method performing client request processing.

        SPEC:
            The authorization server validates the request to ensure that all
            required parameters are present and valid.  If the request is valid,
            the authorization server authenticates the resource owner and obtains
            an authorization decision (by asking the resource owner or by
            establishing approval via other means).

            When a decision is established, the authorization server directs the
            user-agent to the provided client redirection URI using an HTTP
            redirection response, or by other means available to it via the
            user-agent.
        """
        if self.request.POST.get('auth_decision') is None:
            # Obtain an authorization decision by asking the resource owner.
            return self.request_auth_confirmation()

        # User has made his choice using auth form.
        client_id = self.request.session.get('oauth_client_id')
        response_type = self.request.session.get('oauth_response_type')
        redirect_uri = self.request.session.get('oauth_redirect_uri')
        scopes_ids = self.request.session.get('oauth_scopes_ids')
        state = self.request.session.get('oauth_state')

        params_as_uri_fragment = (response_type == 'token')

        if self.request.POST.get('confirmed') is None:
            # User has declined authorization.
            self._clear_session()
            raise ErrorAuthorizeEndpointRedirect(
                self.ERROR_ACCESS_DENIED,
                'Authorization is canceled by user',
                redirect_uri, state, params_as_uri_fragment
            )

        # Simulate scope for filter_scopes()
        self.input_params['scope'] = Scope.objects.filter(id__in=scopes_ids).all()
        client = Client.objects.get(pk=client_id)

        response = self.get_response_document(response_type, redirect_uri, client, params_as_uri_fragment, state)
        self._clear_session()

        return response
