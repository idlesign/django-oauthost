from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

from .endpoints import AuthorizeEndpoint, TokenEndpoint

#todo rename views.py

@login_required
def endpoint_authorize(request):
    return AuthorizeEndpoint(request).get_response()


@csrf_exempt
def endpoint_token(request):
    return TokenEndpoint(request).get_response()
