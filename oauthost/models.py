from uuid import uuid4
from random import randrange

from django.db import models, IntegrityError
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import User

from oauthost.config import *


class Scope(models.Model):

    identifier = models.CharField(_('Scope ID'), max_length=100, help_text=_('Scope identifier.'), unique=True)
    title = models.CharField(_('Scope title'), max_length=250, help_text=_('Scope humanfriendly name.'))

    class Meta:
        verbose_name = _('Scope')
        verbose_name_plural = _('Scopes')
        ordering = ['title']

    def __unicode__(self):
        return '%s' % self.identifier


class Client(models.Model):

    TYPE_CONFIDENTIAL = 1
    TYPE_PUBLIC = 2

    TYPE_CHOICES = (
        (TYPE_CONFIDENTIAL, _('Confidential')),
        (TYPE_PUBLIC, _('Public')),
    )

    date_registered = models.DateTimeField(_('Registered at'), auto_now_add=True)
    title = models.CharField(_('Title'), max_length=100, help_text=_('Name of the client application.'), unique=True)
    user = models.ForeignKey(User, verbose_name=_('User'), help_text=_('User registered this client.'))
    description = models.TextField(_('Description'), max_length=100, help_text=_('Client application description.'))
    link = models.URLField(_('URL'), help_text=_('Client application URL.'), null=True, blank=True)
    identifier = models.CharField(_('Identifier'), max_length=250, help_text=_('Not secret client identifier. <i>If empty will be generated automatically based on client title</i>.'), unique=True, blank=True)
    token_lifetime = models.IntegerField(_('Token lifetime'), help_text=_('Time in seconds after which token expires.'), null=True, blank=True)
    password = models.CharField(_('Password'), max_length=250, help_text=_('Secret that can be used with HTTP Basic authentication scheme with identifier as username.'), blank=True)
    type = models.IntegerField(_('Type'),
       help_text=_('<b>Confidential</b> &#8212; Clients capable of maintaining the confidentiality of their credentials, or capable of secure client authentication using other means.<br /> \
                  <b>Public</b> &#8212; Clients incapable of maintaining the confidentiality of their credentials, and incapable of secure client authentication via any other means'),
       choices=TYPE_CHOICES, default=TYPE_CONFIDENTIAL)
    scopes = models.ManyToManyField(Scope, verbose_name=_('Scopes'), help_text=_('The scopes client is restricted to ask for tokens. <i>All scopes are available for client if none selected.</i>'), null=True, blank=True)
    hash_sign_supported = models.BooleanField(_('Supports # in "Location"'), help_text=_('Should be checked if th client supports fragment component (#) in the HTTP "Location" response header field'), default=True)

    class Meta:
        verbose_name = _('Client')
        verbose_name_plural = _('Clients')

    def __unicode__(self):
        return '%s' % self.title

    def generate_indentifier(self):
        """Identifier length: 32 chars."""
        return str(uuid4()).replace('-', '')

    def save(self, force_insert=False, force_update=False, **kwargs):
        if self.identifier == '':
            while True:
                self.identifier = self.generate_indentifier()
                try:
                    super(Client, self).save(force_insert, force_update, **kwargs)
                except IntegrityError:
                    pass
                else:
                    break
        else:
            super(Client, self).save(force_insert, force_update, **kwargs)


class RedirectionEndpoint(models.Model):

    client = models.ForeignKey(Client, verbose_name=_('Client'))
    uri = models.URLField(_('URI'), help_text=_('Absolute URI or URI pattern for authorization server to redirect client to after completing its interaction with the resource owner.'))

    class Meta:
        verbose_name = _('Redirection Endpoint')
        verbose_name_plural = _('Redirection Endpoints')

    def __unicode__(self):
        return '%s' % self.uri


class AuthorizationCode(models.Model):

    # A maximum authorization code lifetime of 10 minutes is RECOMMENDED
    date_issued = models.DateTimeField(_('Issued at'), auto_now_add=True)
    code = models.CharField(_('Code'), max_length=7, help_text=_('Code issued upon authorization.'), unique=True)
    user = models.ForeignKey(User, verbose_name=_('User'), help_text=_('The user authorization is granted for.'))
    client = models.ForeignKey(Client, verbose_name=_('Client'), help_text=_('The client authorization is granted for.'))
    uri = models.URLField(_('Redirect URI'), help_text=_('Absolute URI authorization is bound to.'))
    scopes = models.ManyToManyField(Scope, verbose_name=_('Scopes'), help_text=_('The scopes token issued from this code should be restricted to.'), null=True, blank=True)

    class Meta:
        verbose_name = _('Authorization code')
        verbose_name_plural = _('Authorization codes')

    def __unicode__(self):
        return '%s' % self.code

    def generate_code(self):
        """Code length: 7 chars."""
        return randrange(1000000, 9999999)

    def save(self, force_insert=False, force_update=False, **kwargs):
        if self.code == '':
            while True:
                self.code = self.generate_code()
                try:
                    super(AuthorizationCode, self).save(force_insert, force_update, **kwargs)
                except IntegrityError:
                    pass
                else:
                    break
        else:
            super(AuthorizationCode, self).save(force_insert, force_update, **kwargs)


class Token(models.Model):

    # A maximum authorization code lifetime of 10 minutes is RECOMMENDED
    date_issued = models.DateTimeField(_('Issued at'), auto_now_add=True)
    expires_at = models.DateTimeField(_('Expires at'), help_text=_('Time when this token expires.'), null=True, blank=True)
    access_token = models.CharField(_('Access Token'), max_length=32, help_text=_('Token to be used to access resources.'), unique=True)
    refresh_token = models.CharField(_('Refresh Token'), max_length=32, help_text=_('Token to be used to refresh access token.'), unique=True, null=True, blank=True)
    access_token_type = models.CharField(_('Type'), max_length=100, help_text=_('Access token type client uses to apply the appropriate authorization method.'), choices=[(t[0], t[1]) for t in REGISTRY_TOKEN_TYPE], default=TOKEN_TYPE_BEARER)
    user = models.ForeignKey(User, verbose_name=_('User'), help_text=_('The user token is issued for.'), null=True, blank=True)
    client = models.ForeignKey(Client, verbose_name=_('Client'), help_text=_('The client application token is issued for.'))
    code = models.ForeignKey(AuthorizationCode, verbose_name=_('Code'), help_text=_('Authorization code used to generate this token.'), null=True, blank=True)
    scopes = models.ManyToManyField(Scope, verbose_name=_('Scopes'), help_text=_('The scopes token is restricted to.'), null=True, blank=True)

    class Meta:
        verbose_name = _('Token')
        verbose_name_plural = _('Tokens')

    def __unicode__(self):
        return '%s' % self.code

    def generate_token(self):
        """Identifier length: 32 chars."""
        return str(uuid4()).replace('-', '')

    def save(self, force_insert=False, force_update=False, **kwargs):
        if self.access_token == '':
            while True:
                self.access_token = self.generate_token()
                self.refresh_token = self.generate_token()

                try:
                    super(Token, self).save(force_insert, force_update, **kwargs)
                except IntegrityError:
                    pass
                else:
                    break
        else:
            super(Token, self).save(force_insert, force_update, **kwargs)
