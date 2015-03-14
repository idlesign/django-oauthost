# encoding: utf-8
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models

class Migration(SchemaMigration):

    def forwards(self, orm):
        
        # Adding model 'Scope'
        db.create_table('oauthost_scope', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('identifier', self.gf('django.db.models.fields.CharField')(unique=True, max_length=100)),
            ('title', self.gf('django.db.models.fields.CharField')(max_length=250)),
        ))
        db.send_create_signal('oauthost', ['Scope'])

        # Adding model 'Client'
        db.create_table('oauthost_client', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('date_registered', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('title', self.gf('django.db.models.fields.CharField')(unique=True, max_length=100)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('description', self.gf('django.db.models.fields.TextField')(max_length=100)),
            ('link', self.gf('django.db.models.fields.URLField')(max_length=200, null=True, blank=True)),
            ('identifier', self.gf('django.db.models.fields.CharField')(unique=True, max_length=250, blank=True)),
            ('token_lifetime', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('password', self.gf('django.db.models.fields.CharField')(max_length=250, blank=True)),
            ('type', self.gf('django.db.models.fields.IntegerField')(default=1)),
            ('hash_sign_supported', self.gf('django.db.models.fields.BooleanField')(default=True)),
        ))
        db.send_create_signal('oauthost', ['Client'])

        # Adding M2M table for field scopes on 'Client'
        db.create_table('oauthost_client_scopes', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('client', models.ForeignKey(orm['oauthost.client'], null=False)),
            ('scope', models.ForeignKey(orm['oauthost.scope'], null=False))
        ))
        db.create_unique('oauthost_client_scopes', ['client_id', 'scope_id'])

        # Adding model 'RedirectionEndpoint'
        db.create_table('oauthost_redirectionendpoint', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('client', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauthost.Client'])),
            ('uri', self.gf('django.db.models.fields.URLField')(max_length=200)),
        ))
        db.send_create_signal('oauthost', ['RedirectionEndpoint'])

        # Adding model 'AuthorizationCode'
        db.create_table('oauthost_authorizationcode', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('date_issued', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('code', self.gf('django.db.models.fields.CharField')(unique=True, max_length=7)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('client', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauthost.Client'])),
            ('uri', self.gf('django.db.models.fields.URLField')(max_length=200)),
        ))
        db.send_create_signal('oauthost', ['AuthorizationCode'])

        # Adding M2M table for field scopes on 'AuthorizationCode'
        db.create_table('oauthost_authorizationcode_scopes', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('authorizationcode', models.ForeignKey(orm['oauthost.authorizationcode'], null=False)),
            ('scope', models.ForeignKey(orm['oauthost.scope'], null=False))
        ))
        db.create_unique('oauthost_authorizationcode_scopes', ['authorizationcode_id', 'scope_id'])

        # Adding model 'Token'
        db.create_table('oauthost_token', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('date_issued', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('expires_at', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('access_token', self.gf('django.db.models.fields.CharField')(unique=True, max_length=32)),
            ('refresh_token', self.gf('django.db.models.fields.CharField')(max_length=32, unique=True, null=True, blank=True)),
            ('access_token_type', self.gf('django.db.models.fields.CharField')(default='bearer', max_length=100)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'], null=True, blank=True)),
            ('client', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauthost.Client'])),
            ('code', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['oauthost.AuthorizationCode'], null=True, blank=True)),
        ))
        db.send_create_signal('oauthost', ['Token'])

        # Adding M2M table for field scopes on 'Token'
        db.create_table('oauthost_token_scopes', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('token', models.ForeignKey(orm['oauthost.token'], null=False)),
            ('scope', models.ForeignKey(orm['oauthost.scope'], null=False))
        ))
        db.create_unique('oauthost_token_scopes', ['token_id', 'scope_id'])


    def backwards(self, orm):
        
        # Deleting model 'Scope'
        db.delete_table('oauthost_scope')

        # Deleting model 'Client'
        db.delete_table('oauthost_client')

        # Removing M2M table for field scopes on 'Client'
        db.delete_table('oauthost_client_scopes')

        # Deleting model 'RedirectionEndpoint'
        db.delete_table('oauthost_redirectionendpoint')

        # Deleting model 'AuthorizationCode'
        db.delete_table('oauthost_authorizationcode')

        # Removing M2M table for field scopes on 'AuthorizationCode'
        db.delete_table('oauthost_authorizationcode_scopes')

        # Deleting model 'Token'
        db.delete_table('oauthost_token')

        # Removing M2M table for field scopes on 'Token'
        db.delete_table('oauthost_token_scopes')


    models = {
        'auth.group': {
            'Meta': {'object_name': 'Group'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        'auth.permission': {
            'Meta': {'ordering': "('content_type__app_label', 'content_type__model', 'codename')", 'unique_together': "(('content_type', 'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        'oauthost.authorizationcode': {
            'Meta': {'object_name': 'AuthorizationCode'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauthost.Client']"}),
            'code': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '7'}),
            'date_issued': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'scopes': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': "orm['oauthost.Scope']", 'null': 'True', 'blank': 'True'}),
            'uri': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        },
        'oauthost.client': {
            'Meta': {'object_name': 'Client'},
            'date_registered': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'description': ('django.db.models.fields.TextField', [], {'max_length': '100'}),
            'hash_sign_supported': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'identifier': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '250', 'blank': 'True'}),
            'link': ('django.db.models.fields.URLField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '250', 'blank': 'True'}),
            'scopes': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': "orm['oauthost.Scope']", 'null': 'True', 'blank': 'True'}),
            'title': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'token_lifetime': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'type': ('django.db.models.fields.IntegerField', [], {'default': '1'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        },
        'oauthost.redirectionendpoint': {
            'Meta': {'object_name': 'RedirectionEndpoint'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauthost.Client']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'uri': ('django.db.models.fields.URLField', [], {'max_length': '200'})
        },
        'oauthost.scope': {
            'Meta': {'ordering': "['title']", 'object_name': 'Scope'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'identifier': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'title': ('django.db.models.fields.CharField', [], {'max_length': '250'})
        },
        'oauthost.token': {
            'Meta': {'object_name': 'Token'},
            'access_token': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '32'}),
            'access_token_type': ('django.db.models.fields.CharField', [], {'default': "'bearer'", 'max_length': '100'}),
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauthost.Client']"}),
            'code': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['oauthost.AuthorizationCode']", 'null': 'True', 'blank': 'True'}),
            'date_issued': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'expires_at': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'refresh_token': ('django.db.models.fields.CharField', [], {'max_length': '32', 'unique': 'True', 'null': 'True', 'blank': 'True'}),
            'scopes': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': "orm['oauthost.Scope']", 'null': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']", 'null': 'True', 'blank': 'True'})
        }
    }

    complete_apps = ['oauthost']
