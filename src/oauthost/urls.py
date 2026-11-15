from django.urls import re_path

from .views import endpoint_authorize, endpoint_token

urlpatterns = [
    re_path(r'^auth/$', endpoint_authorize, name='oauthost_authorize'),

    # SPEC: The [token] endpoint URI MUST NOT include a fragment component.
    re_path(r'^token/$', endpoint_token, name='oauthost_token'),
]
