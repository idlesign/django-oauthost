# django-oauthost

<https://github.com/idlesign/django-oauthost>

[![release](https://img.shields.io/pypi/v/django-oauthost.svg)](https://pypi.python.org/pypi/django-oauthost)
[![lic](https://img.shields.io/pypi/l/django-oauthost.svg)](https://pypi.python.org/pypi/django-oauthost)
[![coverage](https://img.shields.io/coveralls/idlesign/django-oauthost/master.svg)](https://coveralls.io/r/idlesign/django-oauthost)

## What's that

*Reusable application for Django to protect your apps with OAuth 2.0.*

It allows to guard your application views with OAuth 2.0 in quite a trivial way.

1. Register your client using Django Admin or API:

```python
from oauthost.toolbox import register_client

...

# Define some scopes to restrict our client to (if required).
my_scopes = ['polls:vote']

# `user` might be `request.user` if in a view.
register_client('My OAuth Client', 'my_client',
                'http://someurl.com/myclient/', user, scopes_list=my_scopes)

...
```

2. Decorate your views with `oauth_required` (suppose in `polls.views`):

```python
from oauthost.decorators import oauth_required

@oauth_required(scope_auto=True)
def vote(request, poll_id, variant_id):
    ...
```

3. Attach `oauthost.urls` to project `urls` (in `urls.py`):

```python
from oauthost.urls import urlpatterns as oauthost_urlpatterns

urlpatterns = ...  # Your actual urlpatterns are ommited.

urlpatterns += oauthost_urlpatterns
```

Now authorization endpoint is available at `{ BASE_URL }auth/` and token endpoint is available at `{ BASE_URL }token/`.

That's all for **oauthost**, connect using your client.

More information is available, read the docs!

## Documentation

<https://django-oauthost.readthedocs.io/>
