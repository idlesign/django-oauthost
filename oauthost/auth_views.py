import base64

from time import time
from datetime import datetime

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext_lazy as _

from oauthost.models import Client, AuthorizationCode, Token
from oauthost.utils import *
from oauthost.config import *


@login_required
def endpoint_authorize(request):
    """
    SPEC: The authorization endpoint is used to interact with the resource
    owner and obtain an authorization grant.

    SPEC: The authorization server MUST support TLS...
    The authorization server MUST support the use of the HTTP "GET" method [RFC2616]
    for the authorization endpoint, and MAY support the use of the "POST" method as well.

    """

    # SPEC: Since requests to the authorization endpoint result in user authentication
    # and the transmission of clear-text credentials (in the HTTP response),
    # the authorization server MUST require the use of a transport-layer
    # security mechanism when sending requests to the authorization endpoint.
    if not request.is_secure() and not settings.DEBUG:
        # Insecure connections are only available in debug mode.
        return ep_auth_response_error_page(request, _('OAuth requires secure connection to be established.'), 403)

    if request.POST.get('auth_decision') is None:
        # User has made no decision on auth confirmation yet.

        input_params = filter_input_params(request.REQUEST)

        response_type = input_params.get('response_type')
        client_id = input_params.get('client_id')

        redirect_uri = input_params.get('redirect_uri')
        redirect_uri_final = redirect_uri

        if client_id is None:
            # Fail fast without a DB hit.
            return ep_auth_response_error_page(request, _('Client ID must be supplied.'))

        if response_type not in REGISTRY_EP_AUTH_RESPONSE_TYPE:
            return ep_auth_response_error_page(request, _('Unknown response type requested. Expected: %s.') % ', '.join(REGISTRY_EP_AUTH_RESPONSE_TYPE))

        try:
            client = Client.objects.get(identifier=client_id)
        except ObjectDoesNotExist:
            LOGGER.error('Invalid client ID supplied. Value "%s" was sent from IP "%s".' % (client_id, get_remote_ip(request)))
            return ep_auth_response_error_page(request, _('Invalid client ID is supplied.'))

        # TODO There should be at least one redirection URI associated with a client. URI validity should be checked while such an association is made.
        registered_uris = [url[0] for url in client.redirectionendpoint_set.values_list('uri')]

        # Check redirection URI validity.
        if redirect_uri is None:
            # redirect_uri is optional and was not supplied.
            if len(registered_uris) == 1:
                # There is only one URI associated with client, so we use it.
                redirect_uri_final = registered_uris[0]
            else:
                # Several URIs are registered with the client, decision is ambiguous.
                LOGGER.error('Redirect URI is no supplied client with ID "%s". Request from IP "%s".' % (client.id, get_remote_ip(request)))
                return ep_auth_response_error_page(request, _('Redirect URI should be supplied for given client.'))

        # SPEC: The authorization server SHOULD NOT redirect the user-agent to unregistered or untrusted URIs
        # to prevent the authorization endpoint from being used as an open redirector.
        if redirect_uri_final not in registered_uris:
            LOGGER.error('An attempt to use an untrusted URI "%s" for client with ID "%s". Request from IP "%s".' % (redirect_uri_final, client.id, get_remote_ip(request)))
            return ep_auth_response_error_page(request, _('Redirection URI supplied is not associated with given client.'))

        # Access token scope requested,
        scopes_to_apply = resolve_scopes_to_apply(input_params.get('scope'), client)

        request.session['oauth_client_id'] = client.id
        request.session['oauth_response_type'] = response_type
        request.session['oauth_redirect_uri'] = redirect_uri_final
        request.session['oauth_scopes_ids'] = [s.id for s in scopes_to_apply]
        request.session['oauth_state'] = input_params.get('state')

        dict_data = {
            'client': client,
            'scopes_obj': scopes_to_apply,
            'oauthost_title': _('Authorization Request')
        }
        return render(request, OAUTHOST_TEMPLATE_AUTHORIZE, dict_data)

    # ========================================================================================
    # User has made his choice using auth form.

    redirect_uri = request.session.get('oauth_redirect_uri')
    response_type = request.session.get('oauth_response_type')
    params_as_uri_fragment = (response_type == 'token')

    if request.POST.get('confirmed') is None:
        # User has declined authorization.
        ep_auth_clear_session_data(request)
        return ep_auth_response_error(redirect_uri, params_as_uri_fragment, 'access_denied', 'Authorization is canceled by user')

    # User confirmed authorization using a web-form.
    client = Client.objects.get(pk=request.session.get('oauth_client_id'))
    scopes_to_apply = Scope.objects.filter(id__in=request.session.get('oauth_scopes_ids')).all()

    output_params = {}
    auth_obj = None

    # Used for "Authorization code" Grant Type.
    if response_type == 'code':
        # Generating Authorization Code.
        auth_obj = AuthorizationCode(client=client, user=request.user, uri=redirect_uri)
        auth_obj.save()
        output_params['code'] = auth_obj.code

    # Used as "Implicit" Grant Type.
    if response_type == 'token':
        expires_in = client.token_lifetime
        expires_at = None
        if expires_in is not None:
            output_params['expires_in'] = expires_in
            expires_at = datetime.fromtimestamp(int(time() + expires_in))
        # Generating Token.
        auth_obj = Token(client=client, user=request.user, expires_at=expires_at)
        auth_obj.save()
        output_params['access_token'] = auth_obj.access_token
        output_params['token_type'] = auth_obj.access_token_type

    if auth_obj is not None:
        # Link scopes to auth object.
        for scope in scopes_to_apply:
            auth_obj.scopes.add(scope)

    state = request.session.get('state')
    if state is not None:
        output_params['state'] = state

    ep_auth_clear_session_data(request)

    # SPEC: Developers should note that some HTTP client implementations do not
    # support the inclusion of a fragment component in the HTTP "Location"
    # response header field.  Such client will require using other methods
    # for redirecting the client than a 3xx redirection response.
    if not client.hash_sign_supported:
        data_dict = {'action_uri': ep_auth_build_redirect_uri(redirect_uri, output_params, params_as_uri_fragment)}
        return render(request, OAUTHOST_TEMPLATE_AUTHORIZE_PROCEED, data_dict)

    return ep_auth_response(redirect_uri, output_params, params_as_uri_fragment)


@csrf_exempt
def endpoint_token(request):
    """
    SPEC: The token endpoint is used by the client to obtain an access
    token by presenting its authorization grant or refresh token.  The token
    endpoint is used with every authorization grant except for the
    implicit grant type (since an access token is issued directly).

    SPEC: The authorization server MUST support TLS...
    The client MUST use the HTTP "POST" method when making access token requests.

    """

    # SPEC: Since requests to the token endpoint result in the transmission
    # of clear-text credentials (in the HTTP request and response),
    # the authorization server MUST require the use of a transport-layer
    # security mechanism when sending requests to the token endpoint.
    if not request.is_secure() and not settings.DEBUG:
        # Insecure connections are only available in debug mode.
        return ep_auth_response_error_page(request, _('OAuth requires secure connection to be established.'), 403)

    input_params = filter_input_params(request.POST)

    grant_type = input_params.get('grant_type')
    if grant_type not in REGISTRY_EP_TOKEN_GRANT_TYPE:
        return ep_token_reponse_error('unsupported_grant_type', 'Usupported grant type is requested. Expected: `%s`. Given: `%s`' % ('`, `'.join(REGISTRY_EP_TOKEN_GRANT_TYPE), grant_type))

    token_obj_params = {}
    error_out_headers = {}
    client = None
    client_id = None
    client_secret = None

    # TODO More client authentication methods implementations needed.
    authorization_method = request.META.get('Authorization')
    if authorization_method is not None:
        # Authorization header detected.
        auth_method_type, auth_method_value = authorization_method.split(' ', 1)
        error_out_headers['WWW-Authenticate'] = auth_method_type
        # Handle client auth through HTTP Basic.
        if auth_method_type == 'Basic':
            try:
                client_id, client_secret = base64.b64decode(auth_method_value).split(':')
            except Exception:
                pass
    else:
        # SPEC: Including the client credentials in the request body using the two
        # parameters is NOT RECOMMENDED, and should be limited to clients
        # unable to directly utilize the HTTP Basic authentication scheme (or other
        # password-based HTTP authentication schemes).
        client_id = input_params.get('client_id')
        client_secret = input_params.get('client_secret')

    if client_id is not None:
        try:
            client = Client.objects.get(identifier=client_id)
        except ObjectDoesNotExist:
            client = None

        # SPEC: A public client that was not issued a client password MAY use
        # the "client_id" request parameter to identify itself when sending requests
        # to the token endpoint.
        if client is not None:
            if client.password.strip() != '' and client.password != client_secret:
                client = None

    if client is None:
        return ep_token_reponse_error('invalid_client', 'Unable to authenticate client by its credentials.', 401, error_out_headers)

    # Calculate token expiration datetime.
    expires_in = client.token_lifetime
    expires_at = None
    if expires_in is not None:
        expires_at = datetime.fromtimestamp(int(time() + expires_in))

    # TODO Scopes handling implementation required.

    if grant_type == 'authorization_code':  # Grant Type: Authorization code.
        code = input_params.get('code')
        redirect_uri = input_params.get('redirect_uri')

        if code is None or redirect_uri is None:
            return ep_token_reponse_error('invalid_request', 'Required param(s) are missing. Expected: `code` and `redirect_uri`.')

        try:
            code = AuthorizationCode.objects.get(code=code)
        except ObjectDoesNotExist:
            return ep_token_reponse_error('invalid_grant', 'Invalid authorization code is supplied.')

        # SPEC: If an authorization code is used more than once, the authorization
        # server MUST deny the request and SHOULD attempt to revoke all tokens
        # previously issued based on that authorization code.
        previous_tokens = Token.objects.filter(code=code).all()
        if len(previous_tokens) > 0:
            previous_tokens.delete()
            code.delete()
            return ep_token_reponse_error('invalid_grant', 'Authorization code is used more than once. Code and tokens are revoked.')

        if code.uri != redirect_uri:
            return ep_token_reponse_error('invalid_grant', 'Supplied URI does not match the URI associated with authorization code.')

        if code.client.id != client.id:
            return ep_token_reponse_error('invalid_grant', 'Authorization code supplied was issued to another client.')

        user = code.user
        token_obj_params['code'] = code

    elif grant_type == 'password':  # Grant type: Resource Owner Password Credentials.
        username = input_params.get('username')
        password = input_params.get('password')

        if username is None or password is None:
            return ep_token_reponse_error('invalid_request', 'Required param(s) are missing. Expected: `username` and `password`.')

        invalid_credentials = False
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            invalid_credentials = True
        else:
            if not user.check_password(password):
                invalid_credentials = True

        if invalid_credentials:
            return ep_token_reponse_error('invalid_grant', 'Supplied resource owner credentials are invalid.')

    elif grant_type == 'client_credentials':  # Grant type: Client Credentials.
        # That one is somewhat unclear.
        # So let's suppose that the user is one, who has registered the client.
        user = client.user

    elif grant_type == 'refresh_token':  # Refreshing an Access Token.
        refresh_token = input_params.get('refresh_token')

        if refresh_token is None:
            return ep_token_reponse_error('invalid_request', 'Required `refresh_token` param is missing.')

        try:
            token = Token.objects.get(refresh_token=refresh_token)
        except ObjectDoesNotExist:
            return ep_token_reponse_error('invalid_grant', 'Refresh token supplied is invalid.')
        else:
            if token.client_id != client.id:
                return ep_token_reponse_error('invalid_grant', 'Refresh token supplied was issued to another client.')

        # For refresh token grant we only swap token values.
        token.date_issued = datetime.now()
        token.access_token = token.generate_token()
        token.refresh_token = token.generate_token()

    if grant_type != 'refresh_token':
        token = Token(client=client, user=user, expires_at=expires_at, **token_obj_params)

    token.save()

    output_params = {
        'access_token': token.access_token,
        'token_type': token.access_token_type,
        'refresh_token': token.refresh_token
    }

    if expires_in is not None:
        output_params['expires_in'] = expires_in

    if grant_type == 'client_credentials':
        del(output_params['refresh_token'])

    # TODO Some auth methods require additional parameters to be passed as spec puts it.
    additional_params = {}

    return ep_token_response(output_params)
