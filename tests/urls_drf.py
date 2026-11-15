from django.urls import path

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from oauthost.integration.drf import HasScope, OAuthostAuthentication


class PlainView(APIView):
    authentication_classes = [OAuthostAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'user': request.user.username})


class ScopedView(APIView):
    authentication_classes = [OAuthostAuthentication]
    permission_classes = [HasScope]
    required_scopes = ['test:scope']

    def get(self, request):
        return Response({'ok': True})


urlpatterns = [
    path('plain/', PlainView.as_view()),
    path('scoped/', ScopedView.as_view()),
]
