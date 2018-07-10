from uuid import uuid4
from random import randrange

from django.conf import settings
from django.db import models, IntegrityError
from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import python_2_unicode_compatible


from .fields import URLSchemeField
from .settings import REGISTRY_TOKEN_TYPE, TOKEN_TYPE_BEARER


USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')


@python_2_unicode_compatible
class Scope(models.Model):

    STATUS_ENABLED = 1
    STATUS_DISABLED = 2

    STATUS_CHOICES = (
        (STATUS_ENABLED, _('Enabled')),
        (STATUS_DISABLED, _('Disabled')),
    )

    identifier = models.CharField(
        _('Scope ID'), max_length=100, help_text=_('Scope identifier. Usually in form of `app_name:view_name`.'),
        unique=True)

    title = models.CharField(_('Scope title'), max_length=250, help_text=_('Scope human-friendly name.'))

    status = models.PositiveIntegerField(_('Status'), db_index=True, choices=STATUS_CHOICES, default=STATUS_ENABLED)

    class Meta(object):
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

    title = models.CharField(_('Title'), max_length=100, unique=True)

    user = models.ForeignKey(
        USER_MODEL, verbose_name=_('Registrant'), help_text=_('User who registered this client.'),
        on_delete=models.CASCADE)

    description = models.TextField(_('Description'), max_length=100)

    link = models.URLField(_('URL'), help_text=_('Application webpage URL.'), null=True, blank=True)

    identifier = models.CharField(
        _('Identifier'), max_length=250,
        help_text=_('Public client identifier. <i>Generated automatically if empty.</i>.'), unique=True, blank=True)

    token_lifetime = models.IntegerField(
        _('Token lifetime'), help_text=_('Time in seconds after which token given to the application expires.'),
        null=True, blank=True)

    password = models.CharField(
        _('Password'), max_length=250,
        help_text=_('Secret that can be used along with an identifier as username '
                    'to authenticate with HTTP Basic scheme.'),
        blank=True)

    type = models.IntegerField(
        _('Type'),
        help_text=_('<b>Confidential</b> &#8212; Clients capable of maintaining the confidentiality '
                    'of their credentials, or capable of secure client authentication using other means.<br /> '
                    '<b>Public</b> &#8212; Clients incapable of maintaining the confidentiality of their credentials, '
                    'and incapable of secure client authentication via any other means'),
        choices=TYPE_CHOICES, default=TYPE_CONFIDENTIAL)

    scopes = models.ManyToManyField(
        Scope, verbose_name=_('Scopes'),
        help_text=_('The scopes client is restricted to. <i>All registered scopes will be available '
                    'for the client if none selected.</i>'),
        blank=True)

    hash_sign_supported = models.BooleanField(
        _('Supports # in "Location"'),
        help_text=_('Should be checked if this client supports fragment component (#) in the HTTP "Location" '
                    'response header field'),
        default=True)

    class Meta(object):
        verbose_name = _('Client')
        verbose_name_plural = _('Clients')

    def is_public(self):
        return self.type == self.TYPE_PUBLIC

    def is_confidential(self):
        return self.type == self.TYPE_CONFIDENTIAL

    def __str__(self):
        return '%s' % self.title

    @classmethod
    def generate_indentifier(cls):
        """Identifier length: 32 chars."""
        return str(uuid4()).replace('-', '')

    def save(self, force_insert=False, force_update=False, **kwargs):
        if not self.identifier:
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

    client = models.ForeignKey(
        Client, verbose_name=_('Client'), related_name='redirection_uris', on_delete=models.CASCADE)

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
    uri = URLSchemeField(
        _('URI'),
        help_text=_('URI or URI scheme for authorization server to redirect client when an interaction '
                    'with a resource owner is complete.')
    )

    class Meta(object):
        verbose_name = _('Redirection Endpoint')
        verbose_name_plural = _('Redirection Endpoints')

    def __str__(self):
        return '%s' % self.uri


@python_2_unicode_compatible
class AuthorizationCode(models.Model):

    # A maximum authorization code lifetime of 10 minutes is RECOMMENDED
    date_issued = models.DateTimeField(_('Issued at'), auto_now_add=True)
    code = models.CharField(
        _('Code'), max_length=7, unique=True, blank=True,
        help_text=_('Code issued upon authorization.'))
    user = models.ForeignKey(
        USER_MODEL, verbose_name=_('User'), help_text=_('The user authorization is granted for.'),
        on_delete=models.CASCADE)
    client = models.ForeignKey(
        Client, verbose_name=_('Client'), help_text=_('The client authorization is granted for.'),
        on_delete=models.CASCADE)
    uri = URLSchemeField(_('Redirect URI'), help_text=_('The URI authorization is bound to.'))
    scopes = models.ManyToManyField(
        Scope, verbose_name=_('Scopes'),
        help_text=_('The scopes token issued with this code should be restricted to.'), blank=True)

    class Meta(object):
        verbose_name = _('Authorization code')
        verbose_name_plural = _('Authorization codes')

    def __str__(self):
        return '%s' % self.code

    @classmethod
    def generate_code(cls):
        """Code length: 7 chars."""
        return randrange(1000000, 9999999)

    def save(self, force_insert=False, force_update=False, **kwargs):
        if not self.code:
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
    expires_at = models.DateTimeField(_('Expires at'), null=True, blank=True)
    access_token = models.CharField(
        _('Access Token'), max_length=32, help_text=_('Token to be used to access resources.'), unique=True, blank=True)
    refresh_token = models.CharField(
        _('Refresh Token'), max_length=32, help_text=_('Token to be used to refresh access token.'),
        unique=True, null=True, blank=True)
    access_token_type = models.CharField(
        _('Type'), max_length=100,
        help_text=_('Access token type client uses to apply the appropriate authorization method.'),
        choices=[(t[0], t[1]) for t in REGISTRY_TOKEN_TYPE], default=TOKEN_TYPE_BEARER)
    user = models.ForeignKey(
        USER_MODEL, verbose_name=_('User'), help_text=_('The user token is issued for.'), null=True, blank=True,
        on_delete=models.CASCADE)
    client = models.ForeignKey(
        Client, verbose_name=_('Client'), help_text=_('The client application token is issued for.'),
        on_delete=models.CASCADE)
    code = models.ForeignKey(
        AuthorizationCode, verbose_name=_('Code'), help_text=_('Authorization code used to generate this token.'),
        null=True, blank=True, on_delete=models.CASCADE)
    scopes = models.ManyToManyField(
        Scope, verbose_name=_('Scopes'), help_text=_('The scopes token is restricted to.'), blank=True)

    class Meta(object):
        verbose_name = _('Token')
        verbose_name_plural = _('Tokens')

    def __str__(self):
        return '%s' % self.code

    @classmethod
    def generate_token(cls):
        """Identifier length: 32 chars."""
        return str(uuid4()).replace('-', '')

    def save(self, force_insert=False, force_update=False, **kwargs):
        if not self.access_token:
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
