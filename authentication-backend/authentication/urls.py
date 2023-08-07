from django.urls import path
from authentication.views import *
from rest_framework_simplejwt.views import TokenRefreshView

app_name = 'authentication'

urlpatterns = [
    path('activate/<uidb64>/<token>/', account_activate, name='activate-account'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),   
    path('password/reset/', reset_password, name='reset-password'),
    path('password/reset/confirm/', ResetPasswordConfirmView.as_view(), name='reset-password-confirm'),
    path('password/change/', ChangePasswordView.as_view(), name='change-password'),
    path('register/', RegisterView.as_view(), name='user-register'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', CustomTokenVerifyView.as_view(), name='token_verify'),
    path('user/profile/<int:pk>/', UserEmailView.as_view())
]
