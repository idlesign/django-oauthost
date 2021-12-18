from django import VERSION

try:
    from django.urls import re_path

except ImportError:
    # Deprecated in new versions
    from django.conf.urls import url as re_path

from .views import endpoint_authorize, endpoint_token

urlpatterns_list = [
    re_path(r'^auth/$', endpoint_authorize, name='oauthost_authorize'),

    # SPEC: The [token] endpoint URI MUST NOT include a fragment component.
    re_path(r'^token/$', endpoint_token, name='oauthost_token'),
]


if VERSION >= (1, 9):
    urlpatterns = urlpatterns_list
else:
    from django.conf.urls import patterns
    urlpatterns = patterns('oauthost', *urlpatterns_list)
