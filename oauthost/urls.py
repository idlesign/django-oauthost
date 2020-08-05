from django import VERSION

try:
    from django.conf.urls import re_path as url

except ImportError:
    # Deprecated in new versions
    from django.conf.urls import url

from .views import endpoint_authorize, endpoint_token

urlpatterns_list = [
    url(r'^auth/$', endpoint_authorize, name='oauthost_authorize'),

    # SPEC: The [token] endpoint URI MUST NOT include a fragment component.
    url(r'^token/$', endpoint_token, name='oauthost_token'),
]


if VERSION >= (1, 9):
    urlpatterns = urlpatterns_list
else:
    from django.conf.urls import patterns
    urlpatterns = patterns('oauthost', *urlpatterns_list)
