import base64

from time import time
from datetime import datetime

from django import VERSION
from django.conf import settings
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext_lazy as _

from .models import Client, AuthorizationCode, Token, Scope
from .settings import AUTH_ENABLED, LOGGER, REGISTRY_EP_AUTH_RESPONSE_TYPE, TEMPLATE_AUTHORIZE, \
    TEMPLATE_AUTHORIZE_PROCEED, REGISTRY_EP_TOKEN_GRANT_TYPE
from .utils import filter_input_params, ep_auth_response_error_page, get_remote_ip, ep_auth_error_redirect, \
    resolve_scopes_to_apply, ep_auth_clear_session_data, ep_auth_build_redirect_uri, ep_auth_response, \
    ep_token_error_redirect, ep_token_response


if VERSION >= (1, 5):
    from django.contrib.auth import get_user_model
    User = get_user_model()


@login_required
def endpoint_authorize(request):
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

    """

    if not request.is_secure() and not settings.DEBUG:
        # Insecure connections are only available in debug mode.
        return ep_auth_response_error_page(request, _('OAuth requires secure connection.'), 403)

    if request.POST.get('auth_decision') is None:
        # User has made no decision on auth confirmation yet.

        input_params = filter_input_params(request.REQUEST)

        client_id = input_params.get('client_id')  # REQUIRED
        if client_id is None:
            # Fail fast without a DB hit.
            return ep_auth_response_error_page(request, _('Client ID must be supplied.'))

        try:
            client = Client.objects.get(identifier=client_id)
        except ObjectDoesNotExist:
            LOGGER.error('Invalid client ID supplied. Value "%s" was sent from IP "%s".' % (client_id, get_remote_ip(request)))
            return ep_auth_response_error_page(request, _('Invalid client ID is supplied.'))

        redirect_uri = input_params.get('redirect_uri')  # OPTIONAL
        redirect_uri_final = redirect_uri

        registered_uris = [url[0] for url in client.redirectionendpoint_set.values_list('uri')]

        # Check redirection URI validity.
        if redirect_uri is None:
            # redirect_uri is optional and was not supplied.
            if len(registered_uris) == 1:
                # There is only one URI associated with client, so we use it.
                redirect_uri_final = registered_uris[0]
            else:
                # Several URIs are registered with the client, decision is ambiguous.
                LOGGER.error('Redirect URI was not supplied by client with ID "%s". Request from IP "%s".' % (client.id, get_remote_ip(request)))
                return ep_auth_response_error_page(request, _('Redirect URI should be supplied for a given client.'))

        '''
        SPEC:

            The authorization server SHOULD NOT redirect the user-agent to unregistered or untrusted URIs
            to prevent the authorization endpoint from being used as an open redirector.
        '''
        if redirect_uri_final not in registered_uris:
            LOGGER.error('An attempt to use an untrusted URI "%s" for client with ID "%s". Request from IP "%s".' % (redirect_uri_final, client.id, get_remote_ip(request)))
            return ep_auth_response_error_page(request, _('Redirection URI supplied is not associated with given client.'))

        state = input_params.get('state')  # RECOMMENDED

        if not AUTH_ENABLED:
            return ep_auth_error_redirect(redirect_uri, False, 'temporarily_unavailable', 'The authorization server is currently unable to handle the request.', state)

        response_type = input_params.get('response_type')  # REQUIRED
        if response_type not in REGISTRY_EP_AUTH_RESPONSE_TYPE:
            return ep_auth_error_redirect(redirect_uri, False, 'unsupported_response_type', 'Unknown response type requested', state)

        scope = input_params.get('scope')  # OPTIONAL

        # Access token scope requested,
        # todo invalid_scope -- ep_auth_response_error
        scopes_to_apply = resolve_scopes_to_apply(scope, client)

        request.session['oauth_client_id'] = client.id
        request.session['oauth_response_type'] = response_type
        request.session['oauth_redirect_uri'] = redirect_uri_final
        request.session['oauth_scopes_ids'] = [s.id for s in scopes_to_apply]
        request.session['oauth_state'] = state

        dict_data = {
            'client': client,
            'scopes_obj': scopes_to_apply,
            'oauthost_title': _('Authorization Request')
        }
        return render(request, TEMPLATE_AUTHORIZE, dict_data)

    # ========================================================================================
    # User has made his choice using auth form.

    redirect_uri = request.session.get('oauth_redirect_uri')
    response_type = request.session.get('oauth_response_type')
    state = request.session.get('state')
    params_as_uri_fragment = (response_type == 'token')

    if request.POST.get('confirmed') is None:
        # User has declined authorization.
        ep_auth_clear_session_data(request)
        return ep_auth_error_redirect(redirect_uri, params_as_uri_fragment, 'access_denied', 'Authorization is canceled by user', state)

    # User confirmed authorization using a web-form.
    client = Client.objects.get(pk=request.session.get('oauth_client_id'))
    scopes_to_apply = Scope.objects.filter(id__in=request.session.get('oauth_scopes_ids')).all()

    output_params = {}
    auth_obj = None

    if response_type == 'code':
        '''
        SPEC:

        Authorization Code Grant

           The authorization code grant type is used to obtain both access
           tokens and refresh tokens and is optimized for confidential clients.
           Since this is a redirection-based flow, the client must be capable of
           interacting with the resource owner's user-agent (typically a web
           browser) and capable of receiving incoming requests (via redirection)
           from the authorization server.

        '''
        auth_obj = AuthorizationCode(client=client, user=request.user, uri=redirect_uri)
        auth_obj.save()
        output_params['code'] = auth_obj.code

    if response_type == 'token':
        '''
        SPEC:

        Implicit Grant

            The implicit grant type is used to obtain access tokens (it does not
            support the issuance of refresh tokens) and is optimized for public
            clients known to operate a particular redirection URI.  These clients
            are typically implemented in a browser using a scripting language
            such as JavaScript.

        '''
        expires_in = client.token_lifetime
        expires_at = None
        if expires_in is not None:
            output_params['expires_in'] = expires_in  # RECOMMENDED
            expires_at = datetime.fromtimestamp(int(time() + expires_in))
        # Generating Token.
        auth_obj = Token(client=client, user=request.user, expires_at=expires_at)
        auth_obj.save()
        output_params['access_token'] = auth_obj.access_token  # REQUIRED
        output_params['token_type'] = auth_obj.access_token_type  # REQUIRED

    if auth_obj is not None:
        # Link scopes to auth object.
        for scope in scopes_to_apply:
            auth_obj.scopes.add(scope)

    # todo scope OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED

    if state is not None:
        output_params['state'] = state  # REQUIRED if was in request

    ep_auth_clear_session_data(request)

    '''
    SPEC:

       Developers should note that some user-agents do not support the
       inclusion of a fragment component in the HTTP "Location" response
       header field.  Such clients will require using other methods for
       redirecting the client than a 3xx redirection response -- for
       example, returning an HTML page that includes a 'continue' button
       with an action linked to the redirection URI.
    '''
    if not client.hash_sign_supported:
        data_dict = {'action_uri': ep_auth_build_redirect_uri(redirect_uri, output_params, params_as_uri_fragment)}
        return render(request, TEMPLATE_AUTHORIZE_PROCEED, data_dict)

    return ep_auth_response(redirect_uri, output_params, params_as_uri_fragment)


@csrf_exempt
def endpoint_token(request):
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

    """

    if not request.is_secure() and not settings.DEBUG:
        # Insecure connections are only available in debug mode.
        return ep_auth_response_error_page(request, _('OAuth requires secure connection.'), 403)

    input_params = filter_input_params(request.POST)

    grant_type = input_params.get('grant_type')  # REQUIRED
    if grant_type not in REGISTRY_EP_TOKEN_GRANT_TYPE:
        return ep_token_error_redirect('unsupported_grant_type', 'Unsupported grant type is requested. Expected: `%s`. Given: `%s`' % ('`, `'.join(REGISTRY_EP_TOKEN_GRANT_TYPE), grant_type))

    # todo scope
    scope = input_params.get('scope')  # OPTIONAL

    token_obj_params = {}
    error_out_headers = {}
    client = None
    client_id = None
    client_password = None

    authorization_method = request.META.get('Authorization')
    if authorization_method is not None:
        # Authorization header detected.
        auth_method_type, auth_method_value = authorization_method.split(' ', 1)
        error_out_headers['WWW-Authenticate'] = auth_method_type
        # Handle client auth through HTTP Basic.
        if auth_method_type == 'Basic':
            try:
                client_id, client_password = base64.b64decode(auth_method_value).decode('utf-8').split(':')
            except Exception:
                pass
    else:
        '''
        SPEC:
           Alternatively, the authorization server MAY support including the
           client credentials in the request-body using the following
           parameters: client_id, client_secret.

           Including the client credentials in the request-body using the two
           parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
           to directly utilize the HTTP Basic authentication scheme (or other
           password-based HTTP authentication schemes).  The parameters can only
           be transmitted in the request-body and MUST NOT be included in the
           request URI.

           The parameters can only
           be transmitted in the request-body and MUST NOT be included in the
           request URI.
        '''
        client_id = input_params.get('client_id')
        client_password = input_params.get('client_secret')

    if client_id is not None:
        try:
            client = Client.objects.get(identifier=client_id)
        except ObjectDoesNotExist:
            client = None

        '''
        SPEC:

           A client MAY use the "client_id" request parameter to identify itself
           when sending requests to the token endpoint.  In the
           "authorization_code" "grant_type" request to the token endpoint, an
           unauthenticated client MUST send its "client_id" to prevent itself
           from inadvertently accepting a code intended for a client with a
           different "client_id".  This protects the client from substitution of
           the authentication code.  (It provides no additional security for the
           protected resource.)

        '''
        if client is not None:
            if client.password.strip() != '' and client.password != client_password:
                client = None

    if client is None:
        return ep_token_error_redirect('invalid_client', 'Unable to authenticate client by its credentials.', 401, error_out_headers)

    # Calculate token expiration datetime.
    expires_in = client.token_lifetime
    expires_at = None
    if expires_in is not None:
        expires_at = datetime.fromtimestamp(int(time() + expires_in))

    if grant_type == 'authorization_code':
        '''
        Access Token Request

        '''

        code = input_params.get('code')  # REQUIRED
        redirect_uri = input_params.get('redirect_uri')  # REQUIRED

        if code is None or redirect_uri is None:
            return ep_token_error_redirect('invalid_request', 'Required param(s) are missing. Expected: `code` and `redirect_uri`.')

        try:
            code = AuthorizationCode.objects.get(code=code)
        except ObjectDoesNotExist:
            return ep_token_error_redirect('invalid_grant', 'Invalid authorization code is supplied.')

        '''
        SPEC:

            If an authorization code is used more than
            once, the authorization server MUST deny the request and SHOULD
            revoke (when possible) all tokens previously issued based on
            that authorization code.  The authorization code is bound to
            the client identifier and redirection URI.

        '''
        previous_tokens = Token.objects.filter(code=code).all()
        if len(previous_tokens) > 0:
            previous_tokens.delete()
            code.delete()
            return ep_token_error_redirect('invalid_grant', 'Authorization code is used more than once. Code and tokens are revoked.')

        if code.uri != redirect_uri:
            return ep_token_error_redirect('invalid_grant', 'Supplied URI does not match the URI associated with authorization code.')

        if code.client.id != client.id:
            return ep_token_error_redirect('invalid_grant', 'Authorization code supplied was issued to another client.')

        user = code.user
        token_obj_params['code'] = code


    elif grant_type == 'password':
        '''
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

        '''
        username = input_params.get('username')  # REQUIRED
        password = input_params.get('password')  # REQUIRED

        if username is None or password is None:
            return ep_token_error_redirect('invalid_request', 'Required param(s) are missing. Expected: `username` and `password`.')

        invalid_credentials = False
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            invalid_credentials = True
        else:
            if not user.check_password(password):
                invalid_credentials = True

        if invalid_credentials:
            return ep_token_error_redirect('invalid_grant', 'Supplied resource owner credentials are invalid.')


    elif grant_type == 'client_credentials':
        '''
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

        '''

        if not client.is_confidential():
            return ep_token_error_redirect('client_credentials', 'This client type is not authorized to use this grant type.')

        # Let's suppose that the user is the one, who has registered the client.
        user = client.user

    elif grant_type == 'refresh_token':  # Refreshing an Access Token.
        refresh_token = input_params.get('refresh_token')

        if refresh_token is None:
            return ep_token_error_redirect('invalid_request', 'Required `refresh_token` param is missing.')

        try:
            token = Token.objects.get(refresh_token=refresh_token)
        except ObjectDoesNotExist:
            return ep_token_error_redirect('invalid_grant', 'Refresh token supplied is invalid.')
        else:
            if token.client_id != client.id:
                return ep_token_error_redirect('invalid_grant', 'Refresh token supplied was issued to another client.')

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

    # todo scope OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED

    if expires_in is not None:
        output_params['expires_in'] = expires_in

    if grant_type == 'client_credentials':
        del(output_params['refresh_token'])

    return ep_token_response(output_params)
