from .settings import REGISTRY_TOKEN_TYPE


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
