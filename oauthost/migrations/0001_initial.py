# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings
import oauthost.fields


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AuthorizationCode',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('date_issued', models.DateTimeField(auto_now_add=True, verbose_name='Issued at')),
                ('code', models.CharField(help_text='Code issued upon authorization.', unique=True, max_length=7, verbose_name='Code')),
                ('uri', oauthost.fields.URLSchemeField(help_text='The URI authorization is bound to.', verbose_name='Redirect URI')),
            ],
            options={
                'verbose_name': 'Authorization code',
                'verbose_name_plural': 'Authorization codes',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('date_registered', models.DateTimeField(auto_now_add=True, verbose_name='Registered at')),
                ('title', models.CharField(unique=True, max_length=100, verbose_name='Title')),
                ('description', models.TextField(max_length=100, verbose_name='Description')),
                ('link', models.URLField(help_text='Application webpage URL.', null=True, verbose_name='URL', blank=True)),
                ('identifier', models.CharField(help_text='Public client identifier. <i>Generated automatically if empty.</i>.', unique=True, max_length=250, verbose_name='Identifier', blank=True)),
                ('token_lifetime', models.IntegerField(help_text='Time in seconds after which token given to the application expires.', null=True, verbose_name='Token lifetime', blank=True)),
                ('password', models.CharField(help_text='Secret that can be used along with an identifier as username to authenticate with HTTP Basic scheme.', max_length=250, verbose_name='Password', blank=True)),
                ('type', models.IntegerField(default=1, help_text='<b>Confidential</b> &#8212; Clients capable of maintaining the confidentiality of their credentials, or capable of secure client authentication using other means.<br /> <b>Public</b> &#8212; Clients incapable of maintaining the confidentiality of their credentials, and incapable of secure client authentication via any other means', verbose_name='Type', choices=[(1, 'Confidential'), (2, 'Public')])),
                ('hash_sign_supported', models.BooleanField(default=True, help_text='Should be checked if this client supports fragment component (#) in the HTTP "Location" response header field', verbose_name='Supports # in "Location"')),
            ],
            options={
                'verbose_name': 'Client',
                'verbose_name_plural': 'Clients',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='RedirectionEndpoint',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uri', oauthost.fields.URLSchemeField(help_text='URI or URI scheme for authorization server to redirect client when an interaction with a resource owner is complete.', verbose_name='URI')),
                ('client', models.ForeignKey(related_name='redirection_uris', verbose_name='Client', to='oauthost.Client', on_delete=models.CASCADE)),
            ],
            options={
                'verbose_name': 'Redirection Endpoint',
                'verbose_name_plural': 'Redirection Endpoints',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Scope',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('identifier', models.CharField(help_text='Scope identifier. Usually in form of `app_name:view_name`.', unique=True, max_length=100, verbose_name='Scope ID')),
                ('title', models.CharField(help_text='Scope human-friendly name.', max_length=250, verbose_name='Scope title')),
                ('status', models.PositiveIntegerField(default=1, db_index=True, verbose_name='Status', choices=[(1, 'Enabled'), (2, 'Disabled')])),
            ],
            options={
                'ordering': ['title'],
                'verbose_name': 'Scope',
                'verbose_name_plural': 'Scopes',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('date_issued', models.DateTimeField(auto_now_add=True, verbose_name='Issued at')),
                ('expires_at', models.DateTimeField(null=True, verbose_name='Expires at', blank=True)),
                ('access_token', models.CharField(help_text='Token to be used to access resources.', unique=True, max_length=32, verbose_name='Access Token')),
                ('refresh_token', models.CharField(null=True, max_length=32, blank=True, help_text='Token to be used to refresh access token.', unique=True, verbose_name='Refresh Token')),
                ('access_token_type', models.CharField(default='bearer', help_text='Access token type client uses to apply the appropriate authorization method.', max_length=100, verbose_name='Type', choices=[(b'bearer', b'Bearer')])),
                ('client', models.ForeignKey(verbose_name='Client', to='oauthost.Client', help_text='The client application token is issued for.', on_delete=models.CASCADE)),
                ('code', models.ForeignKey(blank=True, to='oauthost.AuthorizationCode', help_text='Authorization code used to generate this token.', null=True, verbose_name='Code', on_delete=models.CASCADE)),
                ('scopes', models.ManyToManyField(help_text='The scopes token is restricted to.', to='oauthost.Scope', null=True, verbose_name='Scopes', blank=True)),
                ('user', models.ForeignKey(blank=True, to=settings.AUTH_USER_MODEL, help_text='The user token is issued for.', null=True, verbose_name='User', on_delete=models.CASCADE)),
            ],
            options={
                'verbose_name': 'Token',
                'verbose_name_plural': 'Tokens',
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='client',
            name='scopes',
            field=models.ManyToManyField(help_text='The scopes client is restricted to. <i>All registered scopes will be available for the client if none selected.</i>', to='oauthost.Scope', null=True, verbose_name='Scopes', blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='client',
            name='user',
            field=models.ForeignKey(verbose_name='Registrant', to=settings.AUTH_USER_MODEL, help_text='User who registered this client.', on_delete=models.CASCADE),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='authorizationcode',
            name='client',
            field=models.ForeignKey(verbose_name='Client', to='oauthost.Client', help_text='The client authorization is granted for.', on_delete=models.CASCADE),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='authorizationcode',
            name='scopes',
            field=models.ManyToManyField(help_text='The scopes token issued with this code should be restricted to.', to='oauthost.Scope', null=True, verbose_name='Scopes', blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='authorizationcode',
            name='user',
            field=models.ForeignKey(verbose_name='User', to=settings.AUTH_USER_MODEL, help_text='The user authorization is granted for.', on_delete=models.CASCADE),
            preserve_default=True,
        ),
    ]
