try:
    from django.conf.urls.defaults import patterns, url
except ImportError:
    # For Django 1.6
    from django.conf.urls import patterns, url


urlpatterns = patterns('oauthost',
    url(r'^auth/$', 'views.endpoint_authorize', name='oauthost_authorize'),
    # SPEC: The [token] endpoint URI MUST NOT include a fragment component.
    url(r'^token/$', 'views.endpoint_token', name='oauthost_token'),
)
