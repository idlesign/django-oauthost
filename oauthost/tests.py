from django.test import TestCase
from django.utils import simplejson as json
from django.test.client import Client as TestClient
from django.contrib.auth.models import User
from django.conf import settings

from oauthost.models import AuthorizationCode, Token, Client, RedirectionEndpoint


URL_TOKEN = '/token/'
URL_AUTHORIZE = '/auth/'


class OAuthostCLient(TestClient):

    def post(self, path, data={}, **extra):
        response = super(OAuthostCLient, self).post(path, data=data, **extra)
        if path == URL_TOKEN:
            response.content_json = json.loads(response.content)
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


class EndpointTokenCheck(TestCase):

    client_class = OAuthostCLient

    def test_grant_authorization_code(self):

        # Secure connection check
        settings.DEBUG = False
        resp = self.client.get(URL_TOKEN, {})
        self.assertEqual(resp.status_code, 403)
        settings.DEBUG = True

        resp = self.client.post(URL_TOKEN, {'grant_type': 'a'})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'unsupported_grant_type')

        user_1 = User(username='Fred')
        user_1.set_password('12345')
        user_1.save()

        client_1 = Client(user=user_1, title='OClient')
        client_1.save()

        redirect_1 = RedirectionEndpoint(client=client_1, uri='http://redirect-test.com')
        redirect_1.save()

        code_1 = AuthorizationCode(user=user_1, client=client_1, uri=redirect_1.uri)
        code_1.save()

        # Missing client authentication data.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code'})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.content_json['error'], 'invalid_client')

        # Missing all required params.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'client_id': client_1.identifier,
                                             'client_secret': client_1.password})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_request')

        # Missing redirect URI.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'code': 'wrong_code',
                                             'client_id': client_1.identifier, 'client_secret': client_1.password})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_request')

        # Missing code.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'redirect_uri': 'http://wrong-url.com',
                                             'client_id': client_1.identifier, 'client_secret': client_1.password})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_request')

        # Wrong code.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'code': 'invalid',
                                             'redirect_uri': 'http://localhost:8000/abc/',
                                             'client_id': client_1.identifier, 'client_secret': client_1.password})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_grant')

        # Wrong URI.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'code': code_1.code,
                                             'redirect_uri': 'http://wrong-url.com/', 'client_id': client_1.identifier,
                                             'client_secret': client_1.password})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_grant')

        # Valid call for a token.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'code': code_1.code,
                                             'redirect_uri': redirect_1.uri, 'client_id': client_1.identifier,
                                             'client_secret': client_1.password})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('access_token' in resp.content_json)
        self.assertTrue('refresh_token' in resp.content_json)
        self.assertTrue('token_type' in resp.content_json)

        # An additional call for code issues token and code invalidation.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'code': '1234567',
                                             'redirect_uri': 'http://localhost:8000/abc/',
                                             'client_id': client_1.identifier, 'client_secret': client_1.password})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_grant')


class EndpointAuthorizeCheck(TestCase):

    client_class = OAuthostCLient

    def test_auth(self):

        # User is not logged in.
        resp = self.client.get(URL_AUTHORIZE, {'client_id': '100'})
        self.assertEqual(resp.status_code, 302)

        user_1 = User(username='Fred')
        user_1.set_password('12345')
        user_1.save()

        # Logging the user in.
        self.client.login(username='Fred', password='12345')

        # Secure connection check
        settings.DEBUG = False
        resp = self.client.get(URL_AUTHORIZE, {})
        self.assertEqual(resp.status_code, 403)
        settings.DEBUG = True

        # Missing client id.
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'code'})
        self.assertEqual(resp.status_code, 400)

        # Missing response type.
        resp = self.client.get(URL_AUTHORIZE, {'client_id': '100'})
        self.assertEqual(resp.status_code, 400)

        # Wrong response type
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'habrahabr'})
        self.assertEqual(resp.status_code, 400)

        # Invalid client id.
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'code', 'client_id': 'invalid'})
        self.assertEqual(resp.status_code, 400)

        client_1 = Client(user=user_1, title='OClient', identifier='cl012345')
        client_1.save()

        client_2 = Client(user=user_1, title='OGOClient')
        client_2.save()

        redirect_1 = RedirectionEndpoint(client=client_1, uri='http://redirect-test.com')
        redirect_1.save()

        redirect_2 = RedirectionEndpoint(client=client_2, uri='http://redirect-test1.com')
        redirect_2.save()

        redirect_3 = RedirectionEndpoint(client=client_2, uri='http://redirect-test2.com')
        redirect_3.save()

        # Client 2 - No redirect URI in request.
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'code', 'client_id': client_2.identifier})
        self.assertEqual(resp.status_code, 400)

        # Client 2 - Unknown URI in request.
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'code', 'redirect_uri': 'http://noitisnot.com', 'client_id': client_2.identifier})
        self.assertEqual(resp.status_code, 400)

        # Valid code request.
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'code', 'client_id': client_1.identifier})
        self.assertEqual(resp.status_code, 200)

        # User declines auth.
        resp = self.client.post(URL_AUTHORIZE, {'auth_decision': 'is_made'})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(parse_location_header(resp)['error'], 'access_denied')

        # Again Valid code request.
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'code', 'client_id': client_1.identifier})
        self.assertEqual(resp.status_code, 200)

        # User confirms auth.
        resp = self.client.post(URL_AUTHORIZE, {'auth_decision': 'is_made', 'confirmed': 'yes'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('code', parse_location_header(resp))

        # ============= Implicit grant tests.

        # Valid token request.
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'token', 'client_id': client_1.identifier})
        self.assertEqual(resp.status_code, 200)

        # User confirms token grant.
        resp = self.client.post(URL_AUTHORIZE, {'auth_decision': 'is_made', 'confirmed': 'yes'})
        self.assertEqual(resp.status_code, 302)
        params = parse_location_header(resp, True)
        self.assertIn('access_token', params)
        self.assertIn('token_type', params)


class GrantsCheck(TestCase):

    client_class = OAuthostCLient

    def test_authorization_code_unsafe(self):

        user_1 = User(username='Fred')
        user_1.set_password('12345')
        user_1.save()

        client_1 = Client(user=user_1, title='OClient')
        client_1.save()

        redirect_1 = RedirectionEndpoint(client=client_1, uri='http://redirect-test.com')
        redirect_1.save()

        # Logging the user in.
        self.client.login(username='Fred', password='12345')

        # Valid code request.
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'code', 'client_id': client_1.identifier})
        self.assertEqual(resp.status_code, 200)

        # User confirms auth.
        resp = self.client.post(URL_AUTHORIZE, {'auth_decision': 'is_made', 'confirmed': 'yes'})
        self.assertEqual(resp.status_code, 302)
        params = parse_location_header(resp)
        self.assertIn('code', params)

        # Auth code given.
        code = params['code']

        # Valid token by code request.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'code': code,
                                             'redirect_uri': redirect_1.uri,
                                             'client_id': client_1.identifier,
                                             'client_secret': client_1.password})

        self.assertEqual(resp.status_code, 200)
        self.assertTrue('access_token' in resp.content_json)
        self.assertTrue('refresh_token' in resp.content_json)
        self.assertTrue('token_type' in resp.content_json)

    def test_authorization_code_http_basic(self):

        user_1 = User(username='Fred')
        user_1.set_password('12345')
        user_1.save()

        client_1 = Client(user=user_1, title='OClient', identifier='OClient', password='cl012345')
        client_1.save()

        redirect_1 = RedirectionEndpoint(client=client_1, uri='http://redirect-test.com')
        redirect_1.save()

        # Logging the user in.
        self.client.login(username='Fred', password='12345')

        # Valid code request.
        resp = self.client.get(URL_AUTHORIZE, {'response_type': 'code', 'client_id': client_1.identifier})
        self.assertEqual(resp.status_code, 200)

        # User confirms auth.
        resp = self.client.post(URL_AUTHORIZE, {'auth_decision': 'is_made', 'confirmed': 'yes'})
        self.assertEqual(resp.status_code, 302)
        params = parse_location_header(resp)
        self.assertIn('code', params)

        # Auth code given.
        code = params['code']

        # Invalid token by code request.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'code': code,
                                             'redirect_uri': redirect_1.uri},
                                Authorization='Basic Tqrqwer==')
        self.assertEqual(resp.status_code, 401)
        self.assertIn('www-authenticate', resp._headers)
        self.assertEqual(resp._headers['www-authenticate'][1], 'Basic')

        # Valid token by code request.
        # HTTP Basic data - OClient:cl012345 --> T0NsaWVudDpjbDAxMjM0NQ==
        resp = self.client.post(URL_TOKEN, {'grant_type': 'authorization_code', 'code': code,
                                             'redirect_uri': redirect_1.uri},
                                Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('access_token' in resp.content_json)
        self.assertTrue('refresh_token' in resp.content_json)
        self.assertTrue('token_type' in resp.content_json)

    def test_token_by_user_credentials(self):

        user_1 = User(username='Fred')
        user_1.set_password('12345')
        user_1.save()

        client_1 = Client(user=user_1, title='OClient', identifier='OClient', password='cl012345')
        client_1.save()

        redirect_1 = RedirectionEndpoint(client=client_1, uri='http://redirect-test.com')
        redirect_1.save()

        # Missing params.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'password'}, Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_request')

        # Invalid params.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'password', 'username': 'FalseUser', 'password': 'FalsePassword'},
                                Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_grant')

        # Valid token by password request.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'password', 'username': 'Fred',
                                             'password': '12345'},
                                Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        self.assertEqual(resp.status_code, 200)
        self.assertTrue('access_token' in resp.content_json)
        self.assertTrue('refresh_token' in resp.content_json)
        self.assertTrue('token_type' in resp.content_json)
        self.assertTrue('expires_in' in resp.content_json)

    def test_token_by_client_credentials(self):

        user_1 = User(username='Fred')
        user_1.set_password('12345')
        user_1.save()

        client_1 = Client(user=user_1, title='OClient', identifier='OClient', password='cl012345')
        client_1.save()

        redirect_1 = RedirectionEndpoint(client=client_1, uri='http://redirect-test.com')
        redirect_1.save()

        # Valid token by client credentials request.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'client_credentials'},
                                Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        self.assertEqual(resp.status_code, 200)
        self.assertTrue('access_token' in resp.content_json)
        self.assertTrue('refresh_token' not in resp.content_json)
        self.assertTrue('token_type' in resp.content_json)

        access_token = resp.content_json['access_token']
        token = Token.objects.get(access_token=access_token)
        self.assertEqual(user_1, token.user)

    def test_refresh_token_http_basic(self):

        user_1 = User(username='Fred')
        user_1.set_password('12345')
        user_1.save()

        client_1 = Client(user=user_1, title='OClient', identifier='OClient', password='cl012345')
        client_1.save()

        client_2 = Client(user=user_1, title='OGOClient', identifier='OGOClient', password='cl543210')
        client_2.save()

        redirect_1 = RedirectionEndpoint(client=client_1, uri='http://redirect-test.com')
        redirect_1.save()

        token_1 = Token(client=client_1, user=user_1)
        token_1.save()

        token_2 = Token(client=client_2, user=user_1)
        token_2.save()

        date_issued = token_1.date_issued
        access_token = token_1.access_token
        refresh_token = token_1.refresh_token

        refresh_token_wrong_client = token_2.refresh_token

        # Missing required params.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'refresh_token'},
                                Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_request')

        # Invalid refresh token supplied.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'refresh_token', 'refresh_token': 'invalid'},
                                Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_grant')

        # Refresh token from another client is supplied.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'refresh_token', 'refresh_token': refresh_token_wrong_client},
                                Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.content_json['error'], 'invalid_grant')

        # Valid request.
        resp = self.client.post(URL_TOKEN, {'grant_type': 'refresh_token', 'refresh_token': refresh_token},
                                Authorization='Basic T0NsaWVudDpjbDAxMjM0NQ==')

        self.assertEqual(resp.status_code, 200)
        self.assertTrue('access_token' in resp.content_json)
        self.assertTrue('refresh_token' in resp.content_json)
        self.assertTrue('token_type' in resp.content_json)
        self.assertTrue('expires_in' not in resp.content_json)

        self.assertNotEqual(access_token, resp.content_json['access_token'])
        self.assertNotEqual(refresh_token, resp.content_json['refresh_token'])

        token_updated = Token.objects.get(access_token=resp.content_json['access_token'])
        self.assertNotEqual(date_issued, token_updated.date_issued)


# TODO Add tests for Bearer auth.
