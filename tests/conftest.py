from itertools import count

import pytest

from pytest_djangoapp import configure_djangoapp_plugin


pytest_plugins = configure_djangoapp_plugin(
    {
        'ROOT_URLCONF': 'oauthost.urls',
        'REST_FRAMEWORK': {'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema'},
    },
    admin_contrib=True,
    extend_INSTALLED_APPS=[
        'django.contrib.sessions',
        'rest_framework',
        'drf_spectacular',
    ],
    extend_MIDDLEWARE=[
        'django.middleware.common.CommonMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
    ],
)


@pytest.fixture
def client_queries(request_client, db_queries):
    """Test client with DB queries counting available via `.db_queries`."""
    client = request_client()
    client.db_queries = db_queries
    return client


@pytest.fixture
def client_oauth(user):
    """Callable fixture creating OAuth clients."""
    from oauthost.models import Client  # noqa: PLC0415

    titles = count(1)

    def client_oauth_(**params):
        params.setdefault('title', f'OClient{next(titles)}')
        client = Client(user=user, **params)
        client.save()
        return client

    return client_oauth_


@pytest.fixture
def redirect_endpoint():
    """Callable fixture creating redirection endpoints."""
    from oauthost.models import RedirectionEndpoint  # noqa: PLC0415

    def redirect_endpoint_(client, uri='http://redirect-test.com'):
        endpoint = RedirectionEndpoint(client=client, uri=uri)
        endpoint.save()
        return endpoint

    return redirect_endpoint_


@pytest.fixture
def auth_code(user):
    """Callable fixture creating authorization codes."""
    from oauthost.models import AuthorizationCode  # noqa: PLC0415

    def auth_code_(client, uri):
        code = AuthorizationCode(user=user, client=client, uri=uri)
        code.save()
        return code

    return auth_code_


@pytest.fixture
def scope_1():
    from oauthost.models import Scope  # noqa: PLC0415

    scope = Scope(identifier='scope1')
    scope.save()
    return scope
