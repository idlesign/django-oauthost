# Django REST framework

oauthost integrates with Django REST framework (DRF) through the optional
module `oauthost.integration.drf`.

!!! note

    `djangorestframework` package is not a hard dependency of oauthost
    and should be installed separately.

## Authentication

`OAuthostAuthentication` authenticates requests carrying a Bearer token
issued by oauthost:

```python
from rest_framework.views import APIView
from oauthost.integration.drf import OAuthostAuthentication

class MyView(APIView):
    authentication_classes = [OAuthostAuthentication]
```

On success `request.user` holds the token owner and `request.auth` holds
the `Token` object. Requests with an invalid or expired token are answered
with `401` and a `WWW-Authenticate: Bearer` header, per RFC 6750.

## Scope checking

`HasScope` permission allows access only if the token grants all scopes
listed in the view's `required_scopes` attribute:

```python
from rest_framework.views import APIView
from oauthost.integration.drf import HasScope, OAuthostAuthentication

class MyView(APIView):
    authentication_classes = [OAuthostAuthentication]
    permission_classes = [HasScope]
    required_scopes = ['polls:vote']
```

Requests with a token lacking the required scopes are answered with `403`.

## OpenAPI (drf-spectacular)

When `drf_spectacular` is listed in `INSTALLED_APPS`, oauthost automatically
registers the `Bearer` security scheme, so views using
`OAuthostAuthentication` are properly described in generated OpenAPI schemas
and work with the Authorize button in Swagger UI.

!!! note

    If you use drf-spectacular without adding it to `INSTALLED_APPS`,
    register the scheme manually by importing the extension module
    before schema generation:

    ```python
    import oauthost.integration.drf_spectacular  # noqa: F401
    ```
