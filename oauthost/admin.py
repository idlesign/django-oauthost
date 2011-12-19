from django.contrib import admin

from oauthost.models import Client, RedirectionEndpoint, AuthorizationCode, Scope, Token


class AuthorizationCodeInlineAdmin(admin.TabularInline):
    model = AuthorizationCode
    extra = 1


class RedirectionEndpointAdmin(admin.TabularInline):
    model = RedirectionEndpoint
    extra = 1


class TokenInlineAdmin(admin.TabularInline):
    model = Token
    extra = 1


class ClientAdmin(admin.ModelAdmin):
    list_display = ('title',)
    list_display_links = ('title',)
    search_fields = ('title',)
    inlines = (RedirectionEndpointAdmin, AuthorizationCodeInlineAdmin, TokenInlineAdmin)


class ScopeAdmin(admin.ModelAdmin):
    list_display = ('title', 'identifier')
    list_display_links = ('title',)
    search_fields = ('title', 'identifier')


class TokenAdmin(admin.ModelAdmin):
    list_display = ('date_issued', 'user', 'access_token', 'access_token_type', 'refresh_token')
    search_fields = ('access_token', 'refresh_token')
    list_filter = ('access_token_type', 'client')
    ordering = ('-date_issued',)
    date_hierarchy = 'date_issued'


class AuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = ('date_issued', 'code', 'client', 'user', 'uri')
    list_display_links = ('code',)
    search_fields = ('code', 'uri')
    list_filter = ('client',)
    ordering = ('-date_issued',)
    date_hierarchy = 'date_issued'


admin.site.register(Client, ClientAdmin)
admin.site.register(Scope, ScopeAdmin)
admin.site.register(Token, TokenAdmin)
admin.site.register(AuthorizationCode, AuthorizationCodeAdmin)
