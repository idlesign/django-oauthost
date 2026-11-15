from unittest.mock import patch

import pytest

from django import forms

from oauthost.models import AuthorizationCode, Client, RedirectionEndpoint, Token


@pytest.fixture
def client_1(client_oauth):
    return client_oauth()


class TestClient:

    def test_type_flags(self, client_1):
        assert client_1.is_confidential()
        assert not client_1.is_public()

        client_1.type = Client.TYPE_PUBLIC

        assert client_1.is_public()
        assert not client_1.is_confidential()

    def test_str_and_preset_identifier(self, client_oauth):
        client = client_oauth(title='Titled', identifier='preset')

        assert str(client) == 'Titled'
        assert client.identifier == 'preset'


class TestAuthorizationCode:

    def test_generated_code(self, client_1, user):
        code = AuthorizationCode(user=user, client=client_1, uri='http://x.com')
        code.save()

        assert str(code) == code.code
        assert len(code.code) == 43

    def test_collision_retry(self, client_1, user):
        code_1 = AuthorizationCode(user=user, client=client_1, uri='http://x.com')
        code_1.save()

        with patch.object(AuthorizationCode, 'generate_code', side_effect=[code_1.code, 'unique']):
            code_2 = AuthorizationCode(user=user, client=client_1, uri='http://x.com')
            code_2.save()

        assert code_2.code == 'unique'


class TestRedirectionEndpoint:

    def test_custom_uri_scheme(self, client_1):
        endpoint = RedirectionEndpoint(client=client_1, uri='myapp://callback')
        endpoint.full_clean()
        endpoint.save()

        assert str(endpoint) == 'myapp://callback'

    def test_formfield_allows_custom_scheme(self):
        field = RedirectionEndpoint._meta.get_field('uri')
        form_field = field.formfield()

        assert isinstance(form_field, forms.URLField)
        assert form_field.clean('myapp://callback') == 'myapp://callback'


class TestToken:

    def test_str(self, client_1, user):
        code = AuthorizationCode(user=user, client=client_1, uri='http://x.com')
        code.save()

        token = Token(client=client_1, user=user, code=code)
        token.save()

        assert str(token) == code.code
