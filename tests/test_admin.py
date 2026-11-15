from django.contrib import admin

from oauthost.models import AuthorizationCode, Client, Scope, Token


class TestAdminRegistration:

    def test_models_registered(self):

        for model in (Client, Scope, Token, AuthorizationCode):
            assert admin.site.is_registered(model)
