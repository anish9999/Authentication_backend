
from django.contrib import auth
from django.utils.http import urlsafe_base64_decode

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from authentication.models import MyUser
from authentication.utils import validate_password, generate_token

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only = True)
    refresh = serializers.CharField(read_only =True)
    access = serializers.CharField(read_only =True)

    class Meta:
        model = MyUser
        fields = ['email', 'password', 'refresh', 'access']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email = email, password = password)
        try:
            user_data = MyUser.objects.get(email=email)
        except:
            raise serializers.ValidationError({'status': 'failed', 'message': 'enter valid email'})
        if not user_data.is_active:
            raise AuthenticationFailed({'status': 'failed', 'message': 'Account is not active.'})
        if not user:
            raise AuthenticationFailed({'status': 'failed', 'message': 'Invalid credentials, Try Again.'})

        tokens = generate_token(user)
        refresh_token = tokens['refresh']
        access_token = tokens['access']
        
        return {
            'email': user.email,
            'refresh': refresh_token,
            'access': access_token
            }

class RegisterSerializer(serializers.ModelSerializer): 
    """
        User registration serializer
    """
    password = serializers.CharField(
        style={'input_type': 'password'},  write_only=True)
    password2 = serializers.CharField(
        style={'input_type': 'password'},  write_only=True)

    class Meta:
        model = MyUser
        fields = [
                    'email', 'password', 'password2', 'is_active',
                ]
        extra_kwargs = {
            'password': {'write_only': True}
        }
        read_only_fields = ['id', 'is_active',]
    
    def save(self, **kwargs):
        user = MyUser(
            email = self.validated_data['email'],
            )

        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        validate_password(password, password2)
        user.set_password(password)
        user.save()

        return user

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=255)

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            serializers.ValidationError({
                'status': 'failed',
                'message': 'Bad refresh token'
            })

class PasswordResetSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = MyUser
        fields = ['email']

class PasswordResetConfirmSerializer(serializers.ModelSerializer):
    uid = serializers.CharField(read_only=True)
    token = serializers.CharField(read_only=True)
    new_password = serializers.CharField(style={'input_type': 'password'}, required=True)

    class Meta:
        model = MyUser
        fields = ['uid', 'token', 'new_password']

    def validate(self, attrs):
        validated_data = super().validate(attrs)
        try:
            uid = urlsafe_base64_decode(self.initial_data.get("uid", ""))
            self.user = MyUser.objects.get(pk=uid)
        except (MyUser.DoesNotExist, ValueError, TypeError, OverflowError):
            key_error = "invalid_uid"
            raise serializers.ValidationError({
                "uid": [self.error_messages[key_error]]}, 
                code=key_error
            )

        is_token_valid = self.context["view"].check_token(
            self.user, self.initial_data.get("token", "")
        )
        if is_token_valid:
            return validated_data
        else:
            raise serializers.ValidationError({
                "token": 'invalid token'
            })

class PasswordChangeSerializer(serializers.ModelSerializer):
    current_password = serializers.CharField(write_only=True, style={'input_type': 'password'}, required=True)
    new_password = serializers.CharField(write_only=True, style={'input_type': 'password'}, required=True)
    re_new_password = serializers.CharField(write_only=True, style={'input_type': 'password'}, required=True)

    class Meta:
        model = MyUser
        fields = ['current_password', 'new_password', 're_new_password']

    def validate(self, attrs):
        old_password = attrs.get('current_password')
        self.validate_old_password(old_password)
        if attrs['new_password'] != attrs['re_new_password']:
            raise serializers.ValidationError({
                "password": "Password fields didn't match."
            })
        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if user.check_password(value)==False:
            raise serializers.ValidationError({
                "current_password": "Old password is not correct"
            })
        return value

    def update(self, instance, validated_data):
        new_password = validated_data['new_password']
        re_new_password = validated_data['re_new_password']
        validate_password(new_password, re_new_password)
        instance.set_password(new_password)
        instance.save()
        return instance