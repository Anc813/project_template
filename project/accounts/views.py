from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.serializers import LoginSerializer


class LoginView(APIView):
    serializer_class = LoginSerializer
    permission_classes = AllowAny,

    def post(self, request, *args, **kwargs):
        username = request.data.get("email")
        password = request.data.get("password")
        if username is None or password is None:
            return Response({'error': 'Please provide both email and password'},
                            status=HTTP_400_BAD_REQUEST)
        user = authenticate(username=username, password=password)
        if not user:
            return Response({'error': 'Invalid Credentials'},
                            status=HTTP_404_NOT_FOUND)
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key},
                        status=HTTP_200_OK)