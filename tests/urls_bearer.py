from django.http import HttpResponse
from django.urls import path

from oauthost.decorators import oauth_required


@oauth_required(scope='test:scope')
def scoped_view(request):
    return HttpResponse('ok')


@oauth_required(scope='other:scope')
def other_view(request):
    return HttpResponse('ok')


@oauth_required(scope_auto=True)
def auto_view(request):
    return HttpResponse('ok')


urlpatterns = [
    path('scoped/', scoped_view),
    path('other/', other_view),
    path('auto/', auto_view),
]
