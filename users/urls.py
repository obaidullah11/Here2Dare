from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from users.views import newSendOTPView,ValidateJWTView,FileUploadnView,RegisterUserView,CheckEmailView,VerifyOTPView,SendOTPView,SendEmailView,UserDetailViewnew,UserDetailView,UpdatePasswordViewnew,UseradminLoginView,ResendOTPView,set_new_password,SocialLoginOrRegisterView,SendPasswordResetEmailView,VerifyOTP,list_users,UserUpdateAPIView, UserChangePasswordView, UserLoginView, UserProfileView, UserRegistrationView,UserDeleteAPIView, UserPasswordResetView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
# from . views import *

urlpatterns = [


    path('check-email/', CheckEmailView.as_view(), name='check_email'),
    path('register/', RegisterUserView.as_view(), name='register-user'),
    path('upload-doc/', FileUploadnView.as_view(), name='upload-doc'),
    path('validate-token/', ValidateJWTView.as_view(), name='validate-token'),

    
    # path('register/', UserRegistrationView.as_view(), name='register'),
    # path('login/', UserLoginView.as_view(), name='login'),
    # path('admin/login/', UseradminLoginView.as_view(), name='login'),

    # path('me/', UserProfileView.as_view(), name='profile'),
    # path('changepassword/<str:custom_id>/', UserChangePasswordView.as_view(), name='change-password'),
    # path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    # path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    # path('account/activation/', VerifyOTP.as_view(), name='verify_otp'),
    # path('updateProfile/<str:custom_id>/', UserUpdateAPIView.as_view(), name='user-update'),
    # path('delete/<str:custom_id>/', UserDeleteAPIView.as_view(), name='user-delete'),
    # path('getallusers/', list_users, name='list_users'),
    # path('social/<str:custom_id>/', UserDetailViewnew.as_view(), name='user_detail'),
    # path('forgotpassword/', set_new_password, name='set_new_password'),
    # path('resend_otp/', ResendOTPView.as_view(), name='resend_otp'),
    # path('api/social_login_or_register/', SocialLoginOrRegisterView.as_view(), name='social_login_or_register'),
    # path('user/<str:id>/', UserDetailView.as_view(), name='user_detail'),
    # path("update-password/", UpdatePasswordViewnew.as_view(), name="update-password"),
    # path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('send-email/', SendEmailView.as_view(), name='send_email'),
    path("register-send-otp/", newSendOTPView.as_view(), name="send_otp"),
    path("send-otp/", SendOTPView.as_view(), name="send_otp"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify_otp"),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)