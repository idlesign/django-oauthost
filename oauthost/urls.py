from django.conf.urls.defaults import patterns, url

urlpatterns = patterns('oauthost',
    url(r'^auth/$', 'auth_views.endpoint_authorize', name='oauthost_authorize'),
    # SPEC: The [token] endpoint URI MUST NOT include a fragment component.
    url(r'^token/$', 'auth_views.endpoint_token', name='oauthost_token'),
)
