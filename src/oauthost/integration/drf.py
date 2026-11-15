"""Integration with Django REST framework.

This module is optional and requires djangorestframework to be installed.

Usage:

    from oauthost.integration.drf import OAuthostAuthentication, HasScope

    class MyView(APIView):
        authentication_classes = [OAuthostAuthentication]
        permission_classes = [HasScope]
        required_scopes = ['my_app:my_scope']

"""
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission

from ..models import Token


class OAuthostAuthentication(BaseAuthentication):
    """Authenticates requests carrying a Bearer token issued by oauthost.

    On success sets `request.user` to the token owner
    and `request.auth` to the Token object.

    """

    www_authenticate_realm = 'api'

    def authenticate(self, request):
        authorization = request.headers.get('Authorization', '')
        auth_type, _, token_value = authorization.partition(' ')

        if auth_type != 'Bearer' or not token_value:
            return None

        token, _ = Token.validate_access_token(token_value)

        if token is None:
            raise exceptions.AuthenticationFailed('Given access token is invalid.')

        return token.user, token

    def authenticate_header(self, request) -> str:
        return f'Bearer realm="{self.www_authenticate_realm}"'


class HasScope(BasePermission):
    """Allows access only if the token grants all scopes
    listed in view's `required_scopes` attribute.

    """

    def has_permission(self, request, view) -> bool:
        required_scopes = getattr(view, 'required_scopes', None)

        if not required_scopes:
            return True

        if isinstance(required_scopes, str):
            required_scopes = [required_scopes]

        token = request.auth

        if token is None:
            return False

        granted_scopes = {scope.identifier for scope in token.scopes.all()}
        return set(required_scopes).issubset(granted_scopes)
