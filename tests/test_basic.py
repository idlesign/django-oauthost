import json
from datetime import timedelta

import pytest

from django.test.client import Client as DjangoClient
from django.utils.timezone import now

from oauthost.models import AuthorizationCode, Token, Client, Scope
from oauthost.toolbox import register_client
from oauthost.exceptions import OauthostException


URL_TOKEN = '/token/'
URL_AUTHORIZE = '/auth/'


class OAuthostClient(DjangoClient):

    def post(self, path, data=None, **extra):
        response = super().post(path, data=data, **extra)
        if path == URL_TOKEN:
            response.content_json = json.loads(response.content.decode('utf-8'))
        return response


def parse_location_header(response, use_uri_fragment=False):
    delimiter = '?'
    if use_uri_fragment:
        delimiter = '#'
    query = response['Location'].split(delimiter)[1]
    query = query.split('&')
    parsed = {}
    for part in query:
        key, value = part.split('=')
        parsed[key] = value
    return parsed


@pytest.fixture
def client():
    return OAuthostClient()


@pytest.fixture
def login(client, user):
    """Logs the user in using the test client."""

    def login_():
        return client.login(username=user.username, password='password')

    return login_


class TestToolbox:

    def test_register_client(self, user):
        scope1 = Scope(identifier='scope1')
        scope1.save()

        cl = register_client('client1_title', 'client1', 'http://client1url.com/client1/', user)
        assert cl.identifier == 'client1'
        assert cl.title == 'client1_title'
        assert cl.user == user

        uris = cl.redirection_uris.all()
        assert len(uris) == 1
        assert uris[0].uri == 'http://client1url.com/client1/'

        with pytest.raises(OauthostException):
            register_client(
                'client2_title', 'client2', 'http://client2url.com/client2/', user,
                scopes_list=[scope1, 'scope2'],
                register_unknown_scopes=False)

        cl = register_client(
            'client2_title', 'client2', 'http://client2url.com/client2/', user,
             scopes_list=[scope1, 'scope2'], token_lifetime=300, public=False,
             client_params={'description': 'client2_decr'})

        assert cl.identifier == 'client2'
        assert cl.title == 'client2_title'
        assert cl.token_lifetime == 300
        assert cl.user == user
        assert cl.description == 'client2_decr'

        assert cl.type != Client.TYPE_PUBLIC

        assert len(cl.scopes.all()) == 2

        uris = cl.redirection_uris.all()
        assert len(uris) == 1
        assert uris[0].uri == 'http://client2url.com/client2/'


class TestEndpointToken:

    def test_grant_authorization_code(self, settings, client, client_oauth, redirect_endpoint, auth_code, scope_1):

        # Secure connection check
        with settings(DEBUG=False):
            resp = client.get(URL_TOKEN, {})
            assert resp.status_code == 403

        settings.DEBUG = True

        resp = client.post(URL_TOKEN, {'grant_type': 'a'})
        assert resp.status_code == 400
        assert resp.content_json['error'] == 'unsupported_grant_type'

        client_1 = client_oauth()
        redirect_1 = redirect_endpoint(client_1)
        code_1 = auth_code(client_1, redirect_1.uri)

        # Missing client authentication data.
        resp = client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'scope': 'scope1'})
        assert resp.status_code == 401
        assert resp.content_json['error'] == 'invalid_client'

        # Missing all required params.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1',
             'client_id': client_1.identifier, 'client_secret': client_1.password})

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_request'

        # Missing redirect URI.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1', 'code': 'wrong_code',
             'client_id': client_1.identifier, 'client_secret': client_1.password})

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_request'

        # Missing code.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1',
             'redirect_uri': 'http://wrong-url.com', 'client_id': client_1.identifier,
             'client_secret': client_1.password})

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_request'

        # Wrong code.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1', 'code': 'invalid',
             'redirect_uri': 'http://localhost:8000/abc/',
             'client_id': client_1.identifier, 'client_secret': client_1.password})

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_grant'

        # Wrong URI.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1', 'code': code_1.code,
             'redirect_uri': 'http://wrong-url.com/', 'client_id': client_1.identifier,
             'client_secret': client_1.password})

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_grant'

        # Valid call for a token.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1', 'code': code_1.code,
             'redirect_uri': redirect_1.uri, 'client_id': client_1.identifier, 'client_secret': client_1.password})

        assert resp.status_code == 200
        assert 'access_token' in resp.content_json
        assert 'refresh_token' in resp.content_json
        assert 'token_type' in resp.content_json

        # An additional call for code issues token and code invalidation.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1', 'code': '1234567',
             'redirect_uri': 'http://localhost:8000/abc/',
             'client_id': client_1.identifier, 'client_secret': client_1.password})

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_grant'

    def test_grant_authorization_code_expired(
            self, settings, client, client_oauth, redirect_endpoint, auth_code, scope_1):

        settings.DEBUG = True

        client_1 = client_oauth()
        redirect_1 = redirect_endpoint(client_1)
        code_1 = auth_code(client_1, redirect_1.uri)

        AuthorizationCode.objects.filter(pk=code_1.pk).update(
            date_issued=now() - timedelta(seconds=601))

        # Expired code is rejected and deleted.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1', 'code': code_1.code,
             'redirect_uri': redirect_1.uri, 'client_id': client_1.identifier,
             'client_secret': client_1.password})

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_grant'
        assert not AuthorizationCode.objects.filter(pk=code_1.pk).exists()

    def test_grant_authorization_code_replay(
            self, settings, client, client_oauth, redirect_endpoint, auth_code, scope_1):

        settings.DEBUG = True

        client_1 = client_oauth()
        redirect_1 = redirect_endpoint(client_1)
        code_1 = auth_code(client_1, redirect_1.uri)

        params = {
            'grant_type': 'authorization_code', 'scope': 'scope1', 'code': code_1.code,
            'redirect_uri': redirect_1.uri, 'client_id': client_1.identifier,
            'client_secret': client_1.password}

        resp = client.post(URL_TOKEN, params)
        assert resp.status_code == 200
        assert Token.objects.filter(code=code_1).count() == 1

        # Code reuse is denied; already issued tokens and the code are revoked.
        resp = client.post(URL_TOKEN, params)
        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_grant'
        assert Token.objects.filter(code=code_1).count() == 0
        assert not AuthorizationCode.objects.filter(pk=code_1.pk).exists()

    def test_grant_authorization_code_another_client(
            self, settings, client, client_oauth, redirect_endpoint, auth_code, scope_1):

        settings.DEBUG = True

        client_1 = client_oauth(identifier='cl1', password='pass1')
        client_2 = client_oauth(identifier='cl2', password='pass2')

        redirect_1 = redirect_endpoint(client_1)
        code_1 = auth_code(client_1, redirect_1.uri)

        # The code was issued to another client.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1', 'code': code_1.code,
             'redirect_uri': redirect_1.uri, 'client_id': client_2.identifier, 'client_secret': 'pass2'})

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_grant'

    def test_client_authentication(self, settings, client, user, client_oauth, scope_1):

        settings.DEBUG = True

        client_1 = client_oauth(identifier='OClient', password='cl012345')

        # Unknown client identifier.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'password', 'scope': 'scope1', 'username': user.username,
             'password': 'password', 'client_id': 'unknown'})

        assert resp.status_code == 401
        assert resp.content_json['error'] == 'invalid_client'

        # Client secret is required but not supplied.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'password', 'scope': 'scope1', 'username': user.username,
             'password': 'password', 'client_id': client_1.identifier})

        assert resp.status_code == 401
        assert resp.content_json['error'] == 'invalid_client'


class TestEndpointAuthorize:

    def test_auth(self, settings, client, login, client_oauth, redirect_endpoint, scope_1):

        # User is not logged in, redirect to login page
        resp = client.get(URL_AUTHORIZE, {'client_id': '100'})
        assert resp.status_code == 302

        # Logging the user in.
        assert login()

        # Secure connection check
        resp = client.get(URL_AUTHORIZE, {})
        assert resp.status_code == 403

        settings.DEBUG = True

        client_1 = client_oauth(identifier='cl012345')
        client_2 = client_oauth()

        redirect_endpoint(client_1)
        redirect_endpoint(client_2, 'http://redirect-test1.com')
        redirect_endpoint(client_2, 'http://redirect-test2.com')

        # Missing client id.
        login()
        resp = client.get(URL_AUTHORIZE, {'response_type': 'code', 'scope': 'scope1'})
        assert resp.status_code == 400

        # Invalid client id.
        login()
        resp = client.get(URL_AUTHORIZE, {'response_type': 'code', 'scope': 'scope1', 'client_id': 'invalid'})
        assert resp.status_code == 400

        # Client 2 - No redirect URI in request.
        login()
        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'code', 'scope': 'scope1', 'client_id': client_2.identifier})

        assert resp.status_code == 400

        # Client 2 - Unknown URI in request.
        login()
        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'code', 'scope': 'scope1',
             'redirect_uri': 'http://noitisnot.com', 'client_id': client_2.identifier})

        assert resp.status_code == 400

        # Missing response type.
        login()
        resp = client.get(URL_AUTHORIZE, {'client_id': client_1.identifier, 'state': 'abc', 'scope': 'scope1'})
        assert resp.status_code == 302
        assert parse_location_header(resp)['error'] == 'unsupported_response_type'
        assert parse_location_header(resp)['state'] == 'abc'

        # Wrong response type
        login()
        resp = client.get(
            URL_AUTHORIZE,
            {'client_id': client_1.identifier, 'response_type': 'habrahabr', 'state': 'abc', 'scope': 'scope1'})

        assert resp.status_code == 302
        assert parse_location_header(resp)['error'] == 'unsupported_response_type'
        assert parse_location_header(resp)['state'] == 'abc'

        # Valid code request.
        login()
        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'code', 'scope': 'scope1', 'state': 'somestate', 'client_id': client_1.identifier})
        assert resp.status_code == 200

        # User declines auth.
        resp = client.post(URL_AUTHORIZE, {'auth_decision': 'is_made'})
        assert resp.status_code == 302
        assert parse_location_header(resp)['error'] == 'access_denied'

        # Again Valid code request.
        login()
        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'code', 'scope': 'scope1', 'state': 'somestatetwo', 'client_id': client_1.identifier})
        assert resp.status_code == 200

        # User confirms auth.
        resp = client.post(URL_AUTHORIZE, {'auth_decision': 'is_made', 'confirmed': 'yes'})
        assert resp.status_code == 302
        assert 'code' in parse_location_header(resp)
        assert parse_location_header(resp)['state'] == 'somestatetwo'

        # ============= Implicit grant tests.

        # Valid token request.
        login()
        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'token', 'scope': 'scope1',
             'state': 'some_state_three', 'client_id': client_1.identifier})

        assert resp.status_code == 200

        # User confirms token grant.
        resp = client.post(URL_AUTHORIZE, {'auth_decision': 'is_made', 'confirmed': 'yes'})
        assert resp.status_code == 302

        params = parse_location_header(resp, True)
        assert 'access_token' in params
        assert 'token_type' in params
        assert params['state'] == 'some_state_three'

    def test_auth_errors(self, settings, client, login, client_oauth, redirect_endpoint, scope_1):

        settings.DEBUG = True

        client_1 = client_oauth()
        redirect_endpoint(client_1)

        login()

        # Invalid client id, request behind a proxy.
        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'code', 'scope': 'scope1', 'client_id': 'invalid'},
            HTTP_X_FORWARDED_FOR='10.1.2.3')

        assert resp.status_code == 400

        # Unsupported scope requested.
        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'code', 'scope': 'unknown', 'state': 'abc', 'client_id': client_1.identifier})

        assert resp.status_code == 302
        assert parse_location_header(resp)['error'] == 'invalid_scope'
        assert parse_location_header(resp)['state'] == 'abc'

    def test_auth_proceed_page(self, settings, client, login, client_oauth, redirect_endpoint, scope_1):

        settings.DEBUG = True

        # Client without support of fragment component in Location header.
        client_1 = client_oauth(hash_sign_supported=False)
        redirect_endpoint(client_1)

        login()

        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'code', 'scope': 'scope1', 'client_id': client_1.identifier})

        assert resp.status_code == 200

        # A continue page is rendered instead of a redirect.
        resp = client.post(URL_AUTHORIZE, {'auth_decision': 'is_made', 'confirmed': 'yes'})

        assert resp.status_code == 200
        assert b'code=' in resp.content


class TestGrants:

    def test_authorization_code_unsafe(self, settings, client, login, client_oauth, redirect_endpoint, scope_1):

        settings.DEBUG = True  # Bypass https requirement

        client_1 = client_oauth()
        redirect_1 = redirect_endpoint(client_1)

        # Logging the user in.
        assert login()

        # Valid code request.
        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'code', 'scope': 'scope1', 'client_id': client_1.identifier})

        assert resp.status_code == 200

        # User confirms auth.
        resp = client.post(URL_AUTHORIZE, {'auth_decision': 'is_made', 'confirmed': 'yes'})
        assert resp.status_code == 302

        params = parse_location_header(resp)
        assert 'code' in params

        # Auth code given.
        code = params['code']

        # Valid token by code request.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1', 'code': code,
             'redirect_uri': redirect_1.uri, 'client_id': client_1.identifier, 'client_secret': client_1.password})

        assert resp.status_code == 200
        assert 'access_token' in resp.content_json
        assert 'refresh_token' in resp.content_json
        assert 'token_type' in resp.content_json

    def test_authorization_code_http_basic(self, settings, client, login, client_oauth, redirect_endpoint, scope_1):

        settings.DEBUG = True  # Bypass https requirement

        client_1 = client_oauth(identifier='OClient', password='cl012345')
        redirect_1 = redirect_endpoint(client_1)

        # Logging the user in.
        login()

        # Valid code request.
        resp = client.get(
            URL_AUTHORIZE,
            {'response_type': 'code', 'scope': 'scope1', 'client_id': client_1.identifier})

        assert resp.status_code == 200

        # User confirms auth.
        resp = client.post(URL_AUTHORIZE, {'auth_decision': 'is_made', 'confirmed': 'yes'})
        assert resp.status_code == 302
        params = parse_location_header(resp)
        assert 'code' in params

        # Auth code given.
        code = params['code']

        # Invalid token by code request.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': redirect_1.uri},
            Authorization='Basic Tqrqwer==')

        assert resp.status_code == 401

        headers = getattr(resp, 'headers', None)
        if headers is None:
            # pre Django 3.2
            header_auth = resp._headers['www-authenticate'][1]
        else:
            header_auth = headers['www-authenticate']

        assert header_auth == 'Basic'

        # Valid token by code request.
        # HTTP Basic data - OClient:cl012345 --> T0NsaWVudDpjbDAxMjM0NQ==
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'authorization_code', 'scope': 'scope1', 'code': code, 'redirect_uri': redirect_1.uri},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 200
        assert 'access_token' in resp.content_json
        assert 'refresh_token' in resp.content_json
        assert 'token_type' in resp.content_json

    def test_scope(self, settings, client, user, client_oauth):

        settings.DEBUG = True

        username = user.username
        password = 'password'

        client_oauth(identifier='OClient', password='cl012345')

        # Scope is missing.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'password', 'username': username, 'password': password},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_scope'

        # No scope supported by server.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'password', 'username': username, 'password': password, 'scope': 'my scope'},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_scope'

        scope1 = Scope(identifier='scope1')
        scope1.save()
        scope2 = Scope(identifier='scope2')
        scope2.save()
        scope3 = Scope(identifier='scope3', status=Scope.STATUS_DISABLED)
        scope3.save()

        client_2 = client_oauth(title='OClien2', identifier='OClient2', password='cl012345')
        client_2.scopes.add(scope2)

        # Unsupported (or disabled) client scope request.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'password', 'username': username, 'password': password, 'scope': 'scope1 scope2'},
            Authorization='Basic T0NsaWVudDI6Y2wwMTIzNDU=')

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_scope'

        # Unsupported (or disabled) server scope request.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'password', 'username': username, 'password': password, 'scope': 'scope1 scope3'},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_scope'

        # Unsupported scope request.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'password', 'username': username, 'password': password, 'scope': 'scope1'},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 200
        assert 'access_token' in resp.content_json
        assert 'refresh_token' in resp.content_json
        assert 'token_type' in resp.content_json
        assert resp.content_json['scope'] == 'scope1'

    def test_token_by_user_credentials(self, settings, client, user, client_oauth, redirect_endpoint, scope_1):

        settings.DEBUG = True

        client_1 = client_oauth(identifier='OClient', password='cl012345', token_lifetime=15)
        redirect_endpoint(client_1)

        # Missing params.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'password', 'scope': 'scope1'},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_request'

        # Invalid params.
        resp = client.post(
            URL_TOKEN,
            {'grant_type': 'password', 'scope': 'scope1', 'username': 'FalseUser', 'password': 'FalsePassword'},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_grant'

        # Valid token by password request.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'password', 'scope': 'scope1', 'username': user.username, 'password': 'password'},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 200
        assert 'access_token' in resp.content_json
        assert 'refresh_token' in resp.content_json
        assert 'token_type' in resp.content_json
        assert 'expires_in' in resp.content_json

    def test_token_by_client_credentials(self, settings, client, user, client_oauth, redirect_endpoint, scope_1):

        settings.DEBUG = True

        client_1 = client_oauth(identifier='OClient', password='cl012345')
        redirect_endpoint(client_1)

        # Valid token by client credentials request.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'client_credentials', 'scope': 'scope1'},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 200
        assert 'access_token' in resp.content_json
        assert 'refresh_token' not in resp.content_json
        assert 'token_type' in resp.content_json

        access_token = resp.content_json['access_token']
        token = Token.objects.get(access_token=access_token)
        assert user == token.user

    def test_token_by_client_credentials_public(self, settings, client, client_oauth, scope_1):

        settings.DEBUG = True

        # Public clients must not use client credentials grant.
        client_1 = client_oauth(type=Client.TYPE_PUBLIC)

        resp = client.post(
            URL_TOKEN, {'grant_type': 'client_credentials', 'scope': 'scope1',
                        'client_id': client_1.identifier})

        assert resp.status_code == 400
        assert 'not authorized' in resp.content_json['error_description']

    def test_refresh_token_http_basic(self, settings, client, user, client_oauth, redirect_endpoint):

        settings.DEBUG = True

        client_1 = client_oauth(identifier='OClient', password='cl012345')
        client_2 = client_oauth(identifier='OGOClient', password='cl543210')

        redirect_endpoint(client_1)

        token_1 = Token(client=client_1, user=user)
        token_1.save()

        token_2 = Token(client=client_2, user=user)
        token_2.save()

        date_issued = token_1.date_issued
        access_token = token_1.access_token
        refresh_token = token_1.refresh_token

        refresh_token_wrong_client = token_2.refresh_token

        # Missing required params.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'refresh_token'},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_request'

        # Invalid refresh token supplied.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'refresh_token', 'refresh_token': 'invalid'},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_grant'

        # Refresh token from another client is supplied.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'refresh_token', 'refresh_token': refresh_token_wrong_client},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 400
        assert resp.content_json['error'] == 'invalid_grant'

        # Valid request.
        resp = client.post(
            URL_TOKEN, {'grant_type': 'refresh_token', 'refresh_token': refresh_token},
            Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        assert resp.status_code == 200
        assert 'access_token' in resp.content_json
        assert 'refresh_token' in resp.content_json
        assert 'token_type' in resp.content_json
        assert 'expires_in' not in resp.content_json

        assert access_token != resp.content_json['access_token']
        assert refresh_token != resp.content_json['refresh_token']

        token_updated = Token.objects.get(access_token=resp.content_json['access_token'])
        assert date_issued != token_updated.date_issued
