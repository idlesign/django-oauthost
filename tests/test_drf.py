import pytest

from datetime import timedelta

from django.utils.timezone import now

from oauthost.models import Scope, Token


@pytest.fixture(autouse=True)
def root_urlconf(settings):
    settings.ROOT_URLCONF = 'urls_drf'


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


class TestOAuthostAuthentication:

    def test_missing_token(self, client_queries):
        response = client_queries.get('/plain/')

        assert response.status_code == 401
        assert response['WWW-Authenticate'] == 'Bearer realm="api"'

    def test_invalid_token(self, client_queries):
        response = client_queries.get('/plain/', HTTP_AUTHORIZATION='Bearer invalid')

        assert response.status_code == 401

    def test_wrong_scheme(self, client_queries, token):
        response = client_queries.get('/plain/', HTTP_AUTHORIZATION=f'Basic {token.access_token}')

        assert response.status_code == 401

    def test_expired_token(self, client_queries, token):
        token.expires_at = now() - timedelta(seconds=10)
        token.save()

        response = client_queries.get('/plain/', **auth_header(token))

        assert response.status_code == 401

    def test_valid_token(self, client_queries, token, user):

        with client_queries.db_queries.scope() as queries:
            response = client_queries.get('/plain/', **auth_header(token))
            assert len(queries.sql()) == 2

        assert response.status_code == 200
        assert response.json() == {'user': user.username}


class TestHasScope:

    def test_sufficient_scope(self, client_queries, token):
        response = client_queries.get('/scoped/', **auth_header(token))

        assert response.status_code == 200

    def test_insufficient_scope(self, client_queries, user, client_oauth):
        token = Token(client=client_oauth(), user=user)
        token.save()

        response = client_queries.get('/scoped/', **auth_header(token))

        assert response.status_code == 403

    def test_missing_token(self, client_queries):
        response = client_queries.get('/scoped/')

        assert response.status_code == 401
