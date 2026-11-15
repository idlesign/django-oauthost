from django.urls import path

from oauthost.views import endpoint_introspect

urlpatterns = [
    path('introspect/', endpoint_introspect),
]
