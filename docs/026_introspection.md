# Token introspection

oauthost implements token introspection per
[RFC 7662](https://tools.ietf.org/html/rfc7662), allowing a resource server
to ask the authorization server whether a token is active and get its
metadata. This is the way to go when the protected site and the
authorization site are different projects not sharing a database.

## Attaching the endpoint

The introspection view is not attached to URLs by default.
Attach it explicitly in your `urls.py`:

```python
from django.urls import path
from oauthost.views import endpoint_introspect

urlpatterns += [
    path('introspect/', endpoint_introspect),
]
```

## Using the endpoint

Requests are made with POST HTTP method. The caller must authenticate
as a **confidential client** (HTTP Basic authorization header or
`client_id` and `client_secret` parameters).

Parameters:

* `token` REQUIRED — token value to introspect (access or refresh).
* `token_type_hint` OPTIONAL — `access_token` or `refresh_token`.

```
POST /introspect/
client_id=resource_server&client_secret=secret&token=987654
```

For an active access token the response contains `active` flag and
token metadata:

```json
{
  "active": true,
  "token_type": "Bearer",
  "scope": "polls:vote",
  "client_id": "my_client",
  "username": "jane",
  "iat": 1763230000,
  "exp": 1763233600
}
```

For an unknown or expired token the response is always
`{"active": false}` with HTTP status 200.
