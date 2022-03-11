from django.shortcuts import render
from rest_framework import generics,status,views,permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken,TokenError,OutstandingToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
import jwt
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from social_auth import serializers




from .serializers import (RegsiterSerializer,EmailVericationSerializer,LoginSerializer,ResetPasswordEmailSerializer,SetNewPasswordSerializer,LogoutSerializer)
from .models import User

from .utils import Util
from .renderers import UserRender

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.shortcuts import redirect
from django.http import HttpResponsePermanentRedirect
# Create your views here.

class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [settings.APP_SCHEME, 'http', 'https']

class RegisterView(generics.GenericAPIView):
    serializer_class = RegsiterSerializer
    renderer_classes = (UserRender,)
    
    def post(self,request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        
        absurl = 'http://'+current_site+relative_link+"?token="+str(token)
        email_body = 'Hi '+user.username+'Use the link below to verify your email\n'+absurl
        data={'email_body':email_body,'to_email':user.email,'email_subject':'Verify your email'}
        Util.send_email(data)
        # print(token)
        # subject = 'Verify your email'
        # message = email_body
        # email_from = settings.EMAIL_HOST_USER
        # recipient_list = [user.email,]
        # print(subject, message, email_from, recipient_list)
        # send_mail( subject, message, email_from, recipient_list )

        return Response(user_data,status=status.HTTP_201_CREATED)

class VerifyEmail(views.APIView):
    serializer_class  = EmailVericationSerializer

    token_param_config = openapi.Parameter('token',in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)
    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self,request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token,settings.SECRET_KEY,algorithms=["HS256"])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified= True
                user.save()
            return Response({"email":"Your email activated successfully"},status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({"error":"Activation Expird"},status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({"error":"Invalid Token"},status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self,request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class=ResetPasswordEmailSerializer
    def post(self,request):
        data ={"request":request,"data":request.data}
        serializer = self.serializer_class(data=data)
        # serializer.is_valid(raise_exception=True)
        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl#+"redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)


            return Response({"success":"We have sent you a link to reset your password","status":True},status=status.HTTP_200_OK)
        return Response({"error":"Email-id does not exist","status":False},status=status.HTTP_400_BAD_REQUEST)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self,request,uidb64,token):
        redirect_url = request.GET.get('redirect_url') #when user mobile app
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                #     if len(redirect_url) > 3:
                #         print('1---')
                #         return CustomRedirect(redirect_url+'?token_valid=False')
                #     else:
                #         print('2---')

                #         return CustomRedirect(settings.FRONTEND_URL+'?token_valid=False')

                # if redirect_url and len(redirect_url) > 3:
                #     print('3---')
                #     return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
                # else:
                #     print('4---')
                #     return CustomRedirect(settings.FRONTEND_URL+'?token_valid=False')
                return Response({"error":"Token is not valid, please request a new one"},status=status.HTTP_400_BAD_REQUEST)

            return Response({"success":True,'message':'Credentails valid','uidb64':uidb64,'token':token},status=status.HTTP_200_OK)

            
        except DjangoUnicodeDecodeError as identifier:
            try:
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)
                # if not PasswordResetTokenGenerator().check_token(user):
                #     return CustomRedirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)

    
class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    
    def patch(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({'success':True,'message':'Password reset success'},status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    # serializer_class = LogoutSerializer

    permission_classes = (permissions.IsAuthenticated,)
    def post(self,request):
        # serializer = self.serializer_class(data=request.data)
        # print("----=======================",serializer)
        # serializer.is_valid(raise_exception=True)
        # serializer.save()
        
        # print(serializer)
        print(request.data['refresh'])
        try:
            RefreshToken(request.data['refresh']).blacklist()
            return Response({'message': "Token blacklisted"})
        except TokenError:
            return Response({'message': "Token is expired or invalid"})
        

queryset = OutstandingToken.objects.all().delete()
print("---------",queryset)