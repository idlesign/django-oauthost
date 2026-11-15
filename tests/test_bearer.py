import pytest

from datetime import timedelta

from django.utils.timezone import now

from oauthost.models import Scope, Token


@pytest.fixture(autouse=True)
def root_urlconf(settings):
    settings.ROOT_URLCONF = 'urls_bearer'


@pytest.fixture
def token(user, client_oauth):
    scope = Scope(identifier='test:scope')
    scope.save()

    token = Token(client=client_oauth(), user=user)
    token.save()
    token.scopes.add(scope)

    return token


def auth_header(token):
    return {'HTTP_AUTHORIZATION': f'Bearer {token.access_token}'}


class TestBearerAuthHandler:
    """Resource protection by Bearer tokens through decorated views."""

    def test_missing_token(self, client_queries):

        with client_queries.db_queries.scope(expect=0):
            response = client_queries.get('/scoped/')

        assert response.status_code == 400
        assert 'invalid_request' in response['WWW-Authenticate']

    def test_unknown_token(self, client_queries):
        response = client_queries.get('/scoped/', HTTP_AUTHORIZATION='Bearer unknown')

        assert response.status_code == 401
        assert 'invalid_token' in response['WWW-Authenticate']

    def test_wrong_token_type(self, client_queries, token):
        token.access_token_type = 'nonbearer'
        token.save()

        response = client_queries.get('/scoped/', **auth_header(token))

        assert response.status_code == 401
        assert 'invalid_token' in response['WWW-Authenticate']

    def test_expired_token(self, client_queries, token):
        token.expires_at = now() - timedelta(seconds=10)
        token.save()

        response = client_queries.get('/scoped/', **auth_header(token))

        assert response.status_code == 401
        assert 'invalid_token' in response['WWW-Authenticate']

    def test_insufficient_scope(self, client_queries, token):
        response = client_queries.get('/other/', **auth_header(token))

        assert response.status_code == 403
        assert 'insufficient_scope' in response['WWW-Authenticate']

    def test_valid_token(self, client_queries, token):

        with client_queries.db_queries.scope() as queries:
            response = client_queries.get('/scoped/', **auth_header(token))
            assert len(queries.sql()) == 7

        assert response.status_code == 200
        assert response.content == b'ok'

    def test_token_from_request_body(self, client_queries, token):
        response = client_queries.post('/scoped/', {'access_token': token.access_token})

        assert response.status_code == 200


class TestScopeAuto:

    def test_scope_auto(self, client_queries, token):
        # The view requires 'urls_bearer:auto_view' scope.
        response = client_queries.get('/auto/', **auth_header(token))
        assert response.status_code == 403

        scope = Scope(identifier='urls_bearer:auto_view')
        scope.save()
        token.scopes.add(scope)

        response = client_queries.get('/auto/', **auth_header(token))
        assert response.status_code == 200
