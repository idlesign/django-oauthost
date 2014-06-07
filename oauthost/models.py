from uuid import uuid4
from random import randrange

from django import VERSION
from django.db import models, IntegrityError
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import python_2_unicode_compatible


from .fields import URLSchemeField
from .settings import REGISTRY_TOKEN_TYPE, TOKEN_TYPE_BEARER


if VERSION >= (1, 5):
    from django.contrib.auth import get_user_model
    User = get_user_model()


@python_2_unicode_compatible
class Scope(models.Model):

    identifier = models.CharField(_('Scope ID'), max_length=100, help_text=_('Scope identifier.'), unique=True)
    title = models.CharField(_('Scope title'), max_length=250, help_text=_('Scope humanfriendly name.'))

    class Meta:
        verbose_name = _('Scope')
        verbose_name_plural = _('Scopes')
        ordering = ['title']

    def __str__(self):
        return '%s' % self.identifier


@python_2_unicode_compatible
class Client(models.Model):

    TYPE_CONFIDENTIAL = 1
    '''
    Clients capable of maintaining the confidentiality of their
    credentials (e.g., client implemented on a secure server with
    restricted access to the client credentials), or capable of secure
    client authentication using other means.

    Examples:

    web application
      A web application is a confidential client running on a web
      server.  Resource owners access the client via an HTML user
      interface rendered in a user-agent on the device used by the
      resource owner.  The client credentials as well as any access
      token issued to the client are stored on the web server and are
      not exposed to or accessible by the resource owner.

    '''

    TYPE_PUBLIC = 2
    '''
    Clients incapable of maintaining the confidentiality of their
    credentials (e.g., clients executing on the device used by the
    resource owner, such as an installed native application or a web
    browser-based application), and incapable of secure client
    authentication via any other means.

    Examples:

    user-agent-based application
      A user-agent-based application is a public client in which the
      client code is downloaded from a web server and executes within a
      user-agent (e.g., web browser) on the device used by the resource
      owner.  Protocol data and credentials are easily accessible (and
      often visible) to the resource owner.  Since such applications
      reside within the user-agent, they can make seamless use of the
      user-agent capabilities when requesting authorization.

    native application
      A native application is a public client installed and executed on
      the device used by the resource owner.  Protocol data and
      credentials are accessible to the resource owner.  It is assumed
      that any client authentication credentials included in the
      application can be extracted.  On the other hand, dynamically
      issued credentials such as access tokens or refresh tokens can
      receive an acceptable level of protection.  At a minimum, these
      credentials are protected from hostile servers with which the
      application may interact.  On some platforms, these credentials
      might be protected from other applications residing on the same
      device.

    '''

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
    hash_sign_supported = models.BooleanField(_('Supports # in "Location"'), help_text=_('Should be checked if this client supports fragment component (#) in the HTTP "Location" response header field'), default=True)

    class Meta:
        verbose_name = _('Client')
        verbose_name_plural = _('Clients')

    def is_public(self):
        return self.type == self.TYPE_PUBLIC

    def is_confidential(self):
        return self.type == self.TYPE_CONFIDENTIAL

    def __str__(self):
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


@python_2_unicode_compatible
class RedirectionEndpoint(models.Model):
    """
    SPEC:

       The authorization server SHOULD require all clients to register their
       redirection endpoint prior to utilizing the authorization endpoint.

       The authorization server MAY allow the client to register multiple
       redirection endpoints.
    """

    client = models.ForeignKey(Client, verbose_name=_('Client'))

    '''
    SPEC:

       The redirection endpoint URI MUST be an absolute URI as defined by
       [RFC3986] Section 4.3.  The endpoint URI MAY include an
       "application/x-www-form-urlencoded" formatted (per Appendix B) query
       component ([RFC3986] Section 3.4), which MUST be retained when adding
       additional query parameters.  The endpoint URI MUST NOT include a
       fragment component.

       If requiring the
       registration of the complete redirection URI is not possible, the
       authorization server SHOULD require the registration of the URI
       scheme, authority, and path (allowing the client to dynamically vary
       only the query component of the redirection URI when requesting
       authorization).

       Lack of a redirection URI registration requirement can enable an
       attacker to use the authorization endpoint as an open redirector as
       described in Section 10.15.

    '''
    uri = URLSchemeField(_('URI'), help_text=_('URI or URI scheme for authorization server to redirect client when an interaction with a resource owner is complete.'))

    class Meta:
        verbose_name = _('Redirection Endpoint')
        verbose_name_plural = _('Redirection Endpoints')

    def __str__(self):
        return '%s' % self.uri


@python_2_unicode_compatible
class AuthorizationCode(models.Model):

    # A maximum authorization code lifetime of 10 minutes is RECOMMENDED
    date_issued = models.DateTimeField(_('Issued at'), auto_now_add=True)
    code = models.CharField(_('Code'), max_length=7, help_text=_('Code issued upon authorization.'), unique=True)
    user = models.ForeignKey(User, verbose_name=_('User'), help_text=_('The user authorization is granted for.'))
    client = models.ForeignKey(Client, verbose_name=_('Client'), help_text=_('The client authorization is granted for.'))
    uri = URLSchemeField(_('Redirect URI'), help_text=_('The URI authorization is bound to.'))
    scopes = models.ManyToManyField(Scope, verbose_name=_('Scopes'), help_text=_('The scopes token issued from this code should be restricted to.'), null=True, blank=True)

    class Meta:
        verbose_name = _('Authorization code')
        verbose_name_plural = _('Authorization codes')

    def __str__(self):
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


@python_2_unicode_compatible
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

    def __str__(self):
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
