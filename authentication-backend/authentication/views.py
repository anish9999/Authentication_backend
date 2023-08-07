
from django import template
from django.conf import settings
from django.middleware import csrf
from django.contrib.auth import logout
from django.utils import timezone
from django.core.mail import BadHeaderError, send_mail
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import redirect

from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView, CreateAPIView, UpdateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.views import TokenVerifyView
from rest_framework_simplejwt.serializers import TokenVerifySerializer
from rest_framework.generics import RetrieveAPIView
from rest_framework_simplejwt.views import TokenObtainPairView


from .utils import get_user_details
from authentication.models import MyUser
from authentication.serializers import LogoutSerializer
from authentication.utils import verify_account, TokenGenerator
from authentication.serializers import *

# from authentication.producer import PublishUser, PublishInvitedUser
class LoginView(TokenObtainPairView):
    """
        This class is for login and also set the cookies in user browser
    """
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data = request.data)
        if(serializer.is_valid(raise_exception=True)):
            response = Response()
            data = serializer.data

            user_data = {
                'id': MyUser.objects.get(email=data['email']).id,
                'email': data['email'],
                'access': data['access'],
                'refresh': data['refresh'],
                'csrf': csrf.get_token(request)
            }
            response.data = {
                'status': 'successful',
                'data': user_data,
                'message': 'Login successful. Take token from cookies'
            }
            response.status_code = status.HTTP_200_OK
            return response
        return Response(data=serializer.data, status=status.HTTP_400_BAD_REQUEST)

class RegisterView(CreateAPIView):
    """
        This class function is to register user through their email
    """
    queryset = MyUser.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        user_data = request.data
        serializer = self.get_serializer(data=user_data)
        if serializer.is_valid(raise_exception=True):
            if self.queryset.filter(email=user_data['email']).exists() == False:
                user = serializer.save(is_active=False)
                current_site = get_current_site(request)
                verify_account(user, current_site)
                response = {
                    'status': 'successful',
                    'message': 'email sent successfully',
                }
                return Response(status = status.HTTP_201_CREATED, data = response)
            response = {
                    'status': 'failed',
                    'message': 'email already registered'
                }
            return Response(status = status.HTTP_400_BAD_REQUEST, data = response)
        response = {
            'status': 'failed',
            'message': 'fill all the fields'
        }
        return Response(status = status.HTTP_400_BAD_REQUEST, data = response)

class LogoutView(GenericAPIView):
    """
        This class is for logout user and remove the cookies from their browser
    """
    permission_classes = (AllowAny,)
    serializer_class = LogoutSerializer

    def post(self, request):
        data = request.data

        serializers = self.serializer_class(data=data)
        serializers.is_valid(raise_exception=True)
        serializers.save()
        logout(request)
        
        data = {
            'status': 'success',
            'message': 'User logged out successfully'
        }
        return Response(data=data, status=status.HTTP_204_NO_CONTENT)
    
@api_view(['GET'])
def account_activate(request, uidb64, token):
    """
        This function is to activate user account through the link which has been sent while registering
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = MyUser._default_manager.get(pk=uid)

    except Exception as e:
        response = {
            'status': 'failed',
            'message': 'Invalid activation link'
        }
        return Response(status = status.HTTP_400_BAD_REQUEST, data = response)

    if TokenGenerator.check_token(user, token):
        user.is_active = True
        user.save()

        response = {
            'status': 'successful',
            'message': 'Account activated.'
        }
        redirect_link = "http://front.localhost.com:3000/signin"
        return redirect(f'{redirect_link}')
        # return Response(status = status.HTTP_200_OK, data = response)
    response = {
        'status': 'failed',
        'message': 'Invalid activation link'
    }
    return Response(status = status.HTTP_400_BAD_REQUEST, data = response)

@swagger_auto_schema(method='post', request_body=openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email')
    }),
    responses={200: 'OK',400: 'Bad Request'})

@api_view(['POST'])
def reset_password(request):
    """
        This function to send email to reset their password i.e. when they click forgot password and new mail will be sent to user email so that 
        they can set new password for their account.
    """
    email = request.data['email']
    if email:
        try:
            email = request.data['email'].lower()
        except:
            return Response({
                'status': 'failed',
                'message': 'Email is required to request rest_password'
            }, status=status.HTTP_400_BAD_REQUEST)
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = MyUser.objects.get(email = email)
        except:
            response = {
                'status': 'failed',
                'message': 'Email not found.'
            }
            return Response(status = status.HTTP_400_BAD_REQUEST, data = response)
        subject = "Password reset"
        message = ""
        htmltemp = template.loader.get_template(
            'account_password_reset_email.html')
        c = {
            "email": user.email,
            'domain': get_current_site(request),
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "user": user,
            'token': default_token_generator.make_token(user),
            'protocol': 'http',
        }
        html_content = htmltemp.render(c)
        try:
            send_mail(subject, message, "noreply@gmail.com",
                            [user.email], fail_silently=False, html_message=html_content)
            response = {
                'status': 'successful',
                'message': "Password reset instructions have been sent to the email address entered.",
            }
            return Response(status = status.HTTP_200_OK, data = response)
        except BadHeaderError:
            response = {
                'status': 'failed',
                'message': 'Invalid header found'
            }
            return Response(status = status.HTTP_400_BAD_REQUEST, data = response)
    return Response({
                'status': 'failed',
                'message': 'Email is required to request rest_password'
            }, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordConfirmView(UpdateAPIView):
    """
        This class is responsible for updating new set password set by user.
    """
    queryset = MyUser.objects.all()
    serializer_class = PasswordResetConfirmSerializer
    token_generator = default_token_generator
    http_method_names = ['put']

    def update(self, request, *args, **kwargs):
        try:
            data = {}
            data['new_password'] = request.data['new_password']
            #appending uid and token from url query param to data
            data['uid'] = self.request.query_params.get('uid')
            data['token'] = self.request.query_params.get('token')
            serializer = self.serializer_class(data=data, context={
                                                        'request': request, 'view': self.token_generator})
            if serializer.is_valid(raise_exception=True):
                new_password = serializer.data['new_password']
                serializer.user.set_password(new_password)
                if hasattr(serializer.user, "last_login"):
                    serializer.user.last_login = timezone.now()
                serializer.user.save()

                response = {
                    'status': 'successful',
                    'message': 'Password restored successfully!'
                }
                return Response(status = status.HTTP_200_OK, data = response)
        except:
            response = {
                'status': 'failed',
                'message': 'check uid, token and choose strong password.'
            }
            return Response(status = status.HTTP_400_BAD_REQUEST, data = response)

class ChangePasswordView(UpdateAPIView):
    """
        This class is to change password when the user are login.
    """
    queryset = MyUser.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer
    http_method_names = ['put']

    def get_object(self):
        return MyUser.objects.get(id=self.request.user.id)

class CustomTokenVerifyView(TokenVerifyView):
    '''
        This class is to verify the access token passed from the request.
        If verified responses with user data.
    '''
    def get(self, request, *args, **kwargs):
        # try:
            token_header = request.META.get('HTTP_AUTHORIZATION')
            token = token_header.replace('Bearer ', '')
            if token is None:
                raise InvalidToken('No token found.')
            serializer = TokenVerifySerializer(data={'token': token})
            serializer.is_valid(raise_exception=True)
            user_id = get_user_details(request)
            user = MyUser.objects.get(id=user_id)
            data = {
                'id': user_id,
                'email': user.email,
            }
            MyUser.objects.filter(id=user_id).update(last_login = timezone.now())
            return Response(data)
            
        # except InvalidToken:
        #     raise AuthenticationFailed('Invalid token')
        # except TokenError as e:
        #     raise AuthenticationFailed('Token is invalid or expired')
        
class UserEmailView(RetrieveAPIView):
    queryset = MyUser.objects.all()
    serializer_class = RegisterSerializer