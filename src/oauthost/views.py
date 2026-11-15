from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt

from .endpoints import AuthorizeEndpoint, IntrospectionEndpoint, TokenEndpoint


@login_required
def endpoint_authorize(request: HttpRequest) -> HttpResponse:
    return AuthorizeEndpoint(request).get_response()


@csrf_exempt
def endpoint_token(request: HttpRequest) -> HttpResponse:
    return TokenEndpoint(request).get_response()


@csrf_exempt
def endpoint_introspect(request: HttpRequest) -> HttpResponse:
    """Token introspection view (RFC 7662). Not attached to URLs by default."""
    return IntrospectionEndpoint(request).get_response()
