import pytest

from datetime import timedelta

from django.utils.timezone import now

from oauthost.models import Client, Scope, Token


URL_INTROSPECT = '/introspect/'


@pytest.fixture(autouse=True)
def root_urlconf(settings):
    settings.ROOT_URLCONF = 'urls_introspect'
    settings.DEBUG = True


@pytest.fixture
def client_rs(client_oauth):
    """Confidential client acting as a resource server."""
    return client_oauth(identifier='rs', password='secret')


@pytest.fixture
def token(user, client_rs):
    scope = Scope(identifier='test:scope')
    scope.save()

    token = Token(client=client_rs, user=user, expires_at=now() + timedelta(hours=1))
    token.save()
    token.scopes.add(scope)

    return token


def introspect(client_queries, client_rs, **params):
    params.update({'client_id': client_rs.identifier, 'client_secret': 'secret'})
    return client_queries.post(URL_INTROSPECT, params)


class TestCallerAuthentication:

    def test_no_auth(self, client_queries):
        response = client_queries.post(URL_INTROSPECT, {'token': 'any'})

        assert response.status_code == 401

    def test_public_client_denied(self, client_queries, client_oauth):
        client_public = client_oauth(type=Client.TYPE_PUBLIC)

        response = client_queries.post(
            URL_INTROSPECT, {'token': 'any', 'client_id': client_public.identifier})

        assert response.status_code == 401

    def test_wrong_secret(self, client_queries, client_rs):
        response = client_queries.post(
            URL_INTROSPECT,
            {'token': 'any', 'client_id': client_rs.identifier, 'client_secret': 'wrong'})

        assert response.status_code == 401


class TestIntrospection:

    def test_missing_token_param(self, client_queries, client_rs):
        response = introspect(client_queries, client_rs)

        assert response.status_code == 400
        assert response.json()['error'] == 'invalid_request'

    def test_unknown_token(self, client_queries, client_rs):
        response = introspect(client_queries, client_rs, token='unknown')

        assert response.status_code == 200
        assert response.json() == {'active': False}

    def test_expired_token(self, client_queries, client_rs, token):
        token.expires_at = now() - timedelta(seconds=10)
        token.save()

        response = introspect(client_queries, client_rs, token=token.access_token)

        assert response.json() == {'active': False}

    def test_valid_access_token(self, client_queries, client_rs, token, user):

        with client_queries.db_queries.scope() as queries:
            response = introspect(client_queries, client_rs, token=token.access_token)
            assert len(queries.sql()) == 3

        document = response.json()

        assert document['active'] is True
        assert document['token_type'] == 'Bearer'
        assert document['client_id'] == client_rs.identifier
        assert document['username'] == user.username
        assert document['scope'] == 'test:scope'
        assert document['exp'] > document['iat']

    def test_refresh_token(self, client_queries, client_rs, token, user):
        response = introspect(client_queries, client_rs, token=token.refresh_token)

        document = response.json()

        assert document['active'] is True
        assert document['token_type'] == 'refresh_token'
        assert 'exp' not in document

    def test_refresh_token_hint(self, client_queries, client_rs, token):
        response = introspect(
            client_queries, client_rs, token=token.refresh_token, token_type_hint='refresh_token')

        assert response.json()['token_type'] == 'refresh_token'
