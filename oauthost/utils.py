from django.contrib.auth import SESSION_KEY
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.utils import simplejson
from django.utils.translation import ugettext_lazy as _

from .models import Scope
from .settings import TEMPLATE_FORBIDDEN, TEMPLATE_AUTHORIZE_ERROR, REGISTRY_TOKEN_TYPE


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

    '''
    SPEC:

       The authorization server MAY fully or partially ignore the scope
       requested by the client, based on the authorization server policy or
       the resource owner's instructions.  If the issued access token scope
       is different from the one requested by the client, the authorization
       server MUST include the "scope" response parameter to inform the
       client of the actual scope granted.
    '''

    # No scopes requested, and we are giving an access to all scopes available.
    # TODO Needs revision.
    if not scopes_requested:
        scopes_to_apply = scopes_available

    # Unavailable scopes are requested.
    scopes_available_set = set(s.identifier for s in scopes_available)
    if set(scopes_requested).difference(scopes_available_set):
        scopes_to_apply_ids = scopes_available_set.intersection(scopes_requested)
        if not scopes_to_apply_ids:
            # Only unavailable scopes are requested.
            # TODO Needs revision.
            scopes_to_apply = []
        else:
            scopes_to_apply = []
            for scope in scopes_available:
                if scope.identifier in scopes_to_apply_ids:
                    scopes_to_apply.append(scope)

    return scopes_to_apply


def ep_auth_response_error_page(request, error_text, http_status=400):
    """For authorization endpoint. Renders a page with error description."""
    data_dict = {'oauthost_title': _('Error'), 'oauthost_error_text': error_text}
    return render(request, TEMPLATE_AUTHORIZE_ERROR, data_dict, status=http_status)


def ep_auth_build_redirect_uri(redirect_base, params, use_uri_fragment):
    """For authorization endpoint. Builds up redirection URL."""
    if use_uri_fragment:
        redirect_base = '%s#' % redirect_base
    else:
        # SPEC: query component MUST be retained when adding additional query parameters.
        if redirect_base is None or '?' not in redirect_base:
            redirect_base = '%s?' % redirect_base
    return '%s%s' % (redirect_base, '&'.join(['%s=%s' % (key, value) for key, value in params.items()]))


def ep_auth_response(redirect_base, params, use_uri_fragment):
    """For authorization endpoint. Issues response."""
    return HttpResponseRedirect(ep_auth_build_redirect_uri(redirect_base, params, use_uri_fragment))


def ep_auth_error_redirect(redirect_to, uri_fragment, error_type, description, state):
    """For authorization endpoint. Issues error response."""
    doc = {'error': error_type, 'error_description': description}
    if state is not None:
        doc.update({'state': state})
    return ep_auth_response(redirect_to, doc, uri_fragment)


def ep_auth_clear_session_data(request):
    """For authorization endpoint. Clears oauth data from session."""
    request.session[SESSION_KEY] = None


def ep_token_response(params, status=200, additional_headers=None):
    """For token endpoint. Issues JSON response."""
    response = HttpResponse(content_type='application/json;charset=UTF-8',
        content=simplejson.dumps(params), status=status)
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    if additional_headers is None:
        additional_headers = {}
    for key, value in additional_headers.items():
        response[key] = value
    return response


def ep_token_error_redirect(error_type, description, status=400, additional_headers=None):
    """For token endpoint. Issues JSON error response."""
    if additional_headers is None:
        additional_headers = {}
    return ep_token_response({'error': error_type, 'error_description': description}, status, additional_headers)


def forbidden_error_response(request):
    """Renders `forbidden` page."""
    return render(request, TEMPLATE_FORBIDDEN, {'oauthost_title': _('Access Denied')}, status=403)


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


class PistonAuthHelper(object):
    """Authentication class for Piston resources.

    To be used in a usual piston-auth-way::

        from piston.resource import Resource
        from oauthost.utils import PistonAuthHelper

        my_resource_view = Resource(MyResourceHandler, authentication=PistonAuthHelper('my_resource:my_scope'))

    """

    def __init__(self, target_scope):
        self.target_scope = target_scope

    def is_authenticated(self, request):
        self.auth_response = auth_handler_response(request, scope=self.target_scope)
        return self.auth_response is None

    def challenge(self):
        return self.auth_response
