from django.contrib.auth import password_validation
from rest_framework import serializers
import threading
from datetime import date
from django.urls import reverse 
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import AccessToken
from six import text_type


def validate_password(password, password2):  
    """
        This function is responsible to validate password
    """  
    try:
        password_validation.validate_password(password)
    except:
        raise serializers.ValidationError({
            'status': 'failed',
            'message': 'i. Password should be atleast 8 characters. ii. Password must not be common. iii. Password must not be entirely numeric.'
        })

    if password != password2:
        raise serializers.ValidationError({
            'status': 'failed',
            'message': 'Password do not match.'
        })



def generate_token(user):
    """
        This function is responsible to generate jwt token for logged in user
    """
    #generating token
    refresh_token = TokenObtainPairSerializer().get_token(user)

    #creating refresh token
    refresh = str(refresh_token)

    #creating access token
    access =  str(refresh_token.access_token)

    tokens = {
        'refresh': refresh,
        'access': access,
    }
    return tokens


def verify_account(user, current_site):
    """
        This function is responsible to send email when user is register in order to confirm whether the email is valid or not
    """
    email_body = {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.id)),
            'token': TokenGenerator.make_token(user)
            
        }
    link = reverse('authentication:activate-account',
                       kwargs={'uidb64': email_body['uid'],
                               'token': email_body['token']
                               })
    activate_url = 'http://'+current_site.domain+link
    email_subject = "Activate your account"
    email_body = f"Hi,\nPlease click this link to verify your account.\n" + activate_url
    email = EmailMessage(
            email_subject,
            email_body,
            'noreply@gmail.com',
            [user.email]
        )
    EmailThread(email).start()


class EmailThread(threading.Thread):
    """
        This class is reponsible to make email sending process faster
    """
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send(fail_silently=False)


class Account_activation(PasswordResetTokenGenerator):
    """
        This class is responsible to has token for user id
    """

    def _make_hash_value(self, user, timestamp):
        return (text_type(user.is_active)+text_type(user.pk)+text_type(timestamp))


TokenGenerator = Account_activation()


def get_user_details(request):
    """
        This function is responsible to get user id from token
    """
    token_header = request.META.get('HTTP_AUTHORIZATION')
    token = token_header.replace('Bearer ', '')
    access_token_str = AccessToken(token)
    user_id = access_token_str['user_id']
    return user_id