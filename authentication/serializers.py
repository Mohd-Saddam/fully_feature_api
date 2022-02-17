from rest_framework import serializers
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str,smart_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from .models import User#,Author,Book,Person
from django.db.models import Count
from django.db.models import F
from django.db.models import Prefetch

# book = Book.objects.values('author').annotate(count = Count('author')).order_by('count')
# print(book.query)
# books = Book.objects.prefetch_related('author').filter(name__iexact=u"JAVA")
# print(books.query)



class RegsiterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68,min_length=4,write_only=True)
    
    class Meta:
        model = User
        fields=['email','username','password']
    
    def validate(self,attrs):
        email = attrs.get('email')
        username = attrs.get('username','')

        if not username.isalnum():
            raise serializers.ValidationError(
                'The username should only contain alphanumeric characters')
        return attrs

    def create(self,validated_data):
        return User.objects.create_user(**validated_data)

class EmailVericationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255,min_length=16)
    password = serializers.CharField(max_length=68,min_length=4,write_only=True)
    username = serializers.EmailField(max_length=255,read_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self,obj):
        user = User.objects.get(email = obj['email'])
        print(user.email)
        # user.tokens()['access'] = user.is_active
        return {
            "access":user.tokens()['access'],
            "refresh":user.tokens()['refresh']
        }

    class Meta:
        model = User
        fields = ['email','password','username','tokens']
    def validate(self,attrs):
        email = attrs.get('email','')
        password = attrs.get('password','')
        user = auth.authenticate(email=email,password=password)
        # import pdb
        # pdb.set_trace()
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email':user.email,
            'username':user.username,
            'tokens':user.tokens
        }
        return super().validate(attrs)


class ResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ['email']

    # def validate(self,attrs):
    #     email = attrs['data'].get('email')
    #     if User.objects.filter(email=email).exists():
    #         user=User.objects.get(email=email)
    #         uidb64 = urlsafe_base64_encode(user.id)
    #         token = PasswordResetTokenGenerator().make_token(user)

    #         current_site = get_current_site(request=attrs['data'].get('requests')).domain
    #         relative_link = reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
            
    #         absurl = 'http://'+current_site+relative_link
    #         email_body = 'Hi '+user.username+'Use link below to reset your password\n'+absurl
    #         data={'email_body':email_body,'to_email':user.email,'email_subject':'Reset your password'}
    #         Util.send_email(data)

        
    #     return super().validate(attrs)

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6,max_length=68,write_only=True)
    token = serializers.CharField(min_length=1,write_only=True)
    uidb64= serializers.CharField(min_length=1,write_only=True)

    class Meta:
        fields = ['password','token','uidb64']
    
    def validate(self,attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user =User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed({'message':'The reset link is invalid'},401)
            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed({'message':'The reset link is invalid'},401)
        return super().validate(attrs)


    pass

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    error_messages  = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self,**kwargs):
        try:
            obj = RefreshToken(self.token).blacklist()
            print("obj------------",obj)
        except TokenError:
            print("error=--------------------",TokenError)
            return  {'bad_token': "Token is expired or invalid"}