from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from users.views import *
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
# from . views import *
user_profile_update = UserProfileViewSet.as_view({'patch': 'update_profile'})
urlpatterns = [


    path('check-email/', CheckEmailView.as_view(), name='check_email'),
    path('register/', RegisterUserView.as_view(), name='register-user'),
    path('upload-doc/', FileUploadnView.as_view(), name='upload-doc'),
    path('validate-token/', ValidateJWTView.as_view(), name='validate-token'),
    path('check-Phonenumber/', CheckPhoneNumberView.as_view(), name='check_email'),
    path("login/", PhoneLoginAPIView.as_view(), name="phone_login"),
    path("getuserprofile/", UserProfileView.as_view(), name="UserProfileView"),
    path('password_reset/', ResetPasswordAPIView.as_view(), name='password_reset'),
    path('social-sign-in/', SocialLoginOrRegisterView.as_view(), name='social-sign-in'),
    path('users/update-profile/', user_profile_update, name='update-profile'),
    path('send-email/', SendEmailView.as_view(), name='send_email'),
    path("register-send-otp/", newSendOTPView.as_view(), name="send_otp"),
    path("send-otp/", SendOTPView.as_view(), name="send_otp"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify_otp"),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)