
import os
from datetime import datetime, timezone
from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from data import helpers
from traceability.models import Traceability

class post_verif_code(APIView):
    permission_classes = []

    def post(self, request):
        input_params = request.data
        try:
            if not "@unal.edu.co" in input_params["email"]:
                raise ValueError("El correo no es dominio @unal.edu.co")

            helpers.sent_email_verif_code(input_params["email"], input_params["id"])

            return JsonResponse({'mensaje': f'Se envió el código de verificación al correo {input_params["email"]}'}, status=status.HTTP_200_OK)
        except Exception as e:
            return JsonResponse({'Error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# Endpoint para NextAuth: recibe el token de Google y autentica/crea usuario
class GoogleAuthAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get('token')
        if not token:
            return JsonResponse({'error': 'Token no proporcionado'}, status=400)
        try:
            # Valida el token con la librería oficial de Google
            idinfo = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                os.getenv('GOOGLE_OAUTH_CLIENT_ID')
            )
            email = idinfo.get('email')
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')
            User = get_user_model()
            user, created = User.objects.get_or_create(email=email, defaults={
                'username': email,
                'first_name': first_name,
                'last_name': last_name,
            })
            # Aquí puedes generar un JWT o sesión si lo necesitas
            return JsonResponse({
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'created': created,
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)