from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.utils import simplejson
from django.utils.translation import ugettext_lazy as _

from oauthost.config import *
from oauthost.models import Scope


def filter_input_params(input_params):
    """Filters request parameters and returns filtered dictionary.

    SPEC: Parameters sent without a value MUST be treated as if they were omitted from the request.

    """
    params_filtered = {}
    for key, value in input_params.items():
        if value:
            params_filtered[key] = value
    return params_filtered


def get_remote_ip(request):
    """Resolves and returns client IP."""

    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = request.META.get('REMOTE_ADDR')
    if forwarded is not None:
        ip = forwarded.split(',')[-1].strip()
    return ip


def resolve_scopes_to_apply(scopes_requested, client):
    """Gets space delimited list of scopes from client request,
    and returns a list of scope objects, corrected according
    to auth server settings.

    """

    if scopes_requested is not None:
        scopes_requested = scopes_requested.split(' ')
    else:
        scopes_requested = []

    scopes_available = []
    scopes_to_apply = []

    # Scopes available to the client.
    for scope in client.scopes.all():
        scopes_available.append(scope)

    # Scopes selection is unrestricted by the client, and we make all scopes available.
    if not scopes_available:
        scopes = Scope.objects.all()
        for scope in scopes:
            scopes_available.append(scope)

    # SPEC: If the issued access token scope is different from the one
    # requested by the client, the authorization server SHOULD include
    # the "scope" response parameter to inform the client of the actual
    # scope granted.

    # No scopes requested, and we are giving an access to all scopes available.
    if not scopes_requested:
        scopes_to_apply = scopes_available

    # Unavailable scopes are requested.
    scopes_available_set = set(s.identifier for s in scopes_available)
    if set(scopes_requested).difference(scopes_available_set):
        scopes_to_apply_ids = scopes_available_set.intersection(scopes_requested)
        # TODO Decision needed.
        # Only unavailable scopes are requested. We give an access to all scopes????
        if not scopes_to_apply_ids:
            scopes_to_apply = scopes_available
        else:
            scopes_to_apply = []
            for scope in scopes_available:
                if scope.identifier in scopes_to_apply_ids:
                    scopes_to_apply.append(scope)

    return scopes_to_apply


def ep_auth_response_error_page(request, error_text, http_status=400):
    """For authorization endpoint. Renders a page with error description."""
    data_dict = {'oauthost_title': _('Error'), 'oauthost_error_text': error_text}
    return render(request, OAUTHOST_TEMPLATE_AUTHORIZE_ERROR, data_dict, status=http_status)


def ep_auth_build_redirect_uri(redirect_base, params, use_uri_fragment):
    """For authorization endpoint. Builds up redirection URL."""
    if use_uri_fragment:
        redirect_base = '%s#' % redirect_base
    else:
        # SPEC: query component MUST be retained when adding additional query parameters.
        if '?' not in redirect_base:
            redirect_base = '%s?' % redirect_base
    return '%s%s' % (redirect_base, '&'.join(['%s=%s' % (key, value) for key, value in params.items()]))


def ep_auth_response(redirect_base, params, use_uri_fragment):
    """For authorization endpoint. Issues response."""
    return HttpResponseRedirect(ep_auth_build_redirect_uri(redirect_base, params, use_uri_fragment))


def ep_auth_response_error(redirect_to, uri_fragment, error_type, description):
    """For authorization endpoint. Issues error response."""
    return ep_auth_response(redirect_to, {'error': error_type, 'error_description': description}, uri_fragment)


def ep_auth_clear_session_data(request):
    """For authorization endpoint. Clears oauth data from session."""
    del request.session['oauth_client_id']
    del request.session['oauth_response_type']
    del request.session['oauth_redirect_uri']
    del request.session['oauth_scopes_ids']
    del request.session['oauth_state']


def ep_token_response(params, status=200, additional_headers={}):
    """For token endpoint. Issues JSON response."""
    response = HttpResponse(content_type='application/json;charset=UTF-8',
        content=simplejson.dumps(params), status=status)
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    for key, value in additional_headers.items():
        response[key] = value
    return response


def ep_token_reponse_error(error_type, description, status=400, additional_headers={}):
    """For token endpoint. Issues JSON error response."""
    return ep_token_response({'error': error_type, 'error_description': description}, status, additional_headers)


def forbidden_error_response(request):
    """Renders `forbidden` page."""
    return render(request, OAUTHOST_TEMPLATE_FORBIDDEN, {'oauthost_title': _('Access Denied')}, status=403)


def auth_handler_response(request, scope=None):
    """Checks for token data in request using various
    methods depending on token types defined in REGISTRY_TOKEN_TYPE.

    ``scope`` - scope identifier string to check token has access to the scope.

    """
    token_auth_classes = [item[2] for item in REGISTRY_TOKEN_TYPE]

    for auth_class in token_auth_classes:
        handler = auth_class(request, scope)
        response = handler.response()
        if response is not None:
            return response

    return None
