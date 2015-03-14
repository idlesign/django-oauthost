from .settings import REGISTRY_TOKEN_TYPE
from .models import Client, Scope, RedirectionEndpoint
from .exceptions import OauthostException


def register_client(title, identifier, redirect_uri, registrant, scopes_list=None, register_unknown_scopes=True,
                    token_lifetime=3600, public=True, client_params=None):
    """Registers a client.

    :param title: client title.
    :param identifier: client identifier
    :param redirect_uri: redirect URI to associate with this client
    :param registrant: user who registeres this client
    :param scopes_list: a list of scope identifiers or Scope objects to restrict the client to.
    :param register_unknown_scopes: this allows to raise OauthostException if scopes_list
        contans an unregistered item instead of registering it.
    :param token_lifetime: lifetime for tokens that'll issued to this client
    :param public: flag to allow, switching from public client type to confidential
    :param client_params: arbitary parameters to build a Client object from
    :return: client object
    :rtype: Client
    """
    client_kwargs = {}

    if client_params is not None:
        client_kwargs.update(client_params)

    client_kwargs.update({
        'title': title,
        'identifier': identifier,
        'user': registrant,
        'token_lifetime': token_lifetime,
    })

    if public:
        client_kwargs['type'] = Client.TYPE_PUBLIC
    else:
        client_kwargs['type'] = Client.TYPE_CONFIDENTIAL

    target_scope_objects = []
    if scopes_list:
        registered_scopes_ = Scope.objects.filter(identifier__in=scopes_list).all()
        registered_scopes = {}
        for scope in registered_scopes_:
            registered_scopes[scope.identifier] = scope
        del registered_scopes_

        for scope in scopes_list:
            scope_obj = scope
            if not isinstance(scope, Scope):
                if scope in registered_scopes:
                    scope_obj = registered_scopes[scope]
                else:
                    if register_unknown_scopes:
                        scope_obj = Scope(identifier=scope, title=scope)
                        scope_obj.save()
                    else:
                        raise OauthostException('Unable to register client to an unknown `%s` scope.' % scope)

            target_scope_objects.append(scope_obj)

    cl = Client(**client_kwargs)
    cl.save()

    for scope_obj in target_scope_objects:
        cl.scopes.add(scope_obj)

    if redirect_uri is not None:
        RedirectionEndpoint(uri=redirect_uri, client=cl).save()

    return cl


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
        self.auth_response = None

    def is_authenticated(self, request):
        self.auth_response = auth_handler_response(request, scope=self.target_scope)
        return self.auth_response is None

    def challenge(self):
        return self.auth_response
