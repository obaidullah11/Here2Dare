from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.http import JsonResponse
from rest_framework import status
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from users.serializers import UserUpdateSerializer,SendPasswordResetEmailSerializer,DriverSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserRegistrationSerializer
from django.contrib.auth import authenticate
from users.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .models import User
from rest_framework.views import APIView
from django.contrib.auth.hashers import make_password
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from .serializers import UserSerializer,SocialRegistrationSerializer, UserLoginSerializer,PasswordResetSerializer
from django.contrib.auth.hashers import make_password
import random
from rest_framework.exceptions import ValidationError
import string
from django.conf import settings
from twilio.rest import Client
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from rest_framework.decorators import api_view
from django.core.mail import send_mail
from django.http import JsonResponse
import json
import json
from django.core.mail import send_mail
from django.http import JsonResponse
from rest_framework.decorators import api_view
from users.serializers import EmailSerializer
from rest_framework.generics import GenericAPIView
from drf_yasg.utils import swagger_auto_schema

from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from twilio.rest import Client
import random

from .serializers import SendOTPSerializer, VerifyOTPSerializer



from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from twilio.rest import Client
import random

from .serializers import SendOTPSerializer, VerifyOTPSerializer

# Temporary OTP storage (Use Redis or database in production)

from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .serializers import RegisterUserSerializer 
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from twilio.rest import Client
import random
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .serializers import  UserProfileSerializer,RegisterUserSerializer,SendOTPSerializer, VerifyOTPSerializer,EmailExistenceCheckResponseSerializer,EmailExistenceCheckSerializer
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from .models import User,DocumentVerification # Adjust to your actual User model
from django.core.validators import EmailValidator
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from .serializers import FileUploadSerializern

from .models import User
from PIL import Image
from io import BytesIO
from django.core.files.uploadedfile import InMemoryUploadedFile
# from .serializers import UserProfileSerializer

# In your view, serialize the data like this
# user_data = UserProfileSerializer(User).data
from drf_yasg import openapi

from .serializers import FileUploadSerializern

from django.core.files.uploadedfile import InMemoryUploadedFile
from PIL import Image
from io import BytesIO
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from .serializers import FileUploadSerializern, UserProfileSerializer
from .models import DocumentVerification
from rest_framework.permissions import IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class FileUploadnView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure user is authenticated via JWT
    parser_classes = (MultiPartParser, FormParser)  # Allows for file uploads

    @swagger_auto_schema(
        operation_description="Upload a file",
        request_body=FileUploadSerializern,
        responses={
            200: openapi.Response('File uploaded successfully'),
            400: openapi.Response('Bad Request'),
        },
        tags=['Signup Flow']
    )
    def post(self, request):
        serializer = FileUploadSerializern(data=request.data)
        if serializer.is_valid():
            # Handle file saving or further processing here
            file = serializer.validated_data['file']
            file_size = file.size

            # Check if the file size is greater than 1 MB (1 MB = 1048576 bytes)
            if file_size > 1048576:
                # Compress the image file to 1 MB
                try:
                    # Open the file using Pillow (assuming it's an image)
                    image = Image.open(file)

                    # Calculate quality and compression level to reduce size
                    image_io = BytesIO()
                    quality = 85  # Adjust quality to achieve a smaller file size

                    image.save(image_io, format='JPEG', quality=quality)
                    image_io.seek(0)

                    # Create a new file-like object to use the compressed file
                    compressed_file = InMemoryUploadedFile(
                        image_io,
                        'ImageField',
                        file.name,
                        'image/jpeg',
                        image_io.tell(),
                        None
                    )

                    # Now compressed_file can be used like the original file
                    file = compressed_file  # Reassign the compressed file back
                except Exception as e:
                    return Response({
                        'success': False,
                        'message': 'Error compressing file.',
                        'error': str(e)
                    }, status=status.HTTP_400_BAD_REQUEST)

            # Create a new DocumentVerification entry for the user
            user = request.user  # Get the authenticated user from the request
            document_verification = DocumentVerification.objects.create(
                user=user,
                document_file=file,
                verification_status='Pending',  # Set default verification status to Pending
            )

            # Update the 'document_uploaded' field of the currently authenticated user
            user.document_uploaded = True  # Set the document_uploaded field to True
            user.save()  # Save the user instance with the updated field

            # Serialize user data for response
            user_profile = UserProfileSerializer(user)  # Serialize the user object

            return Response({
                'success': True,
                'message': 'File uploaded and verification initiated successfully.',
                'data': {
                    'file_name': file.name,
                    'file_size': file.size,
                    'document_uploaded': user.document_uploaded,  # Optional: Including the updated field in the response
                    'user_profile': user_profile.data,  # Return serialized user data
                    'verification_status': document_verification.verification_status  # Return the status of the verification
                }
            }, status=status.HTTP_200_OK)

        return Response({
            'success': False,
            'message': 'File upload failed.',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class CheckEmailView(APIView):
    """
    API endpoint to check if an email is already registered.
    """

    @swagger_auto_schema(
        operation_description="Check if an email is already registered",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL, description="Email to check"),
            },
            required=['email']
        ),
        responses={
            200: openapi.Response(
                description="Email existence check",
                examples={"application/json": {"success": True, "message": "Email is available", "exists": False}}
            ),
            400: openapi.Response(description="Invalid email format"),
        }, tags=['Signup Flow']
    )
    def post(self, request):
        email = request.data.get('email', '')

        # Validate email format
        try:
            EmailValidator()(email)
        except ValidationError:
            return Response({'success': False, 'message': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if email exists
        exists = User.objects.filter(email=email).exists()

        if exists:
            return Response({'success': True, 'message': 'Email is already taken', 'exists': True}, status=status.HTTP_200_OK)
        else:
            return Response({'success': True, 'message': 'Email is available', 'exists': False}, status=status.HTTP_200_OK)







































OTP_STORAGE = {}

class newSendOTPView(APIView):
    """
    Send OTP via Twilio to the given phone number after checking if the user exists.
    """
    
    @swagger_auto_schema(
        request_body=SendOTPSerializer,
        responses={200: openapi.Response("OTP sent successfully!", SendOTPSerializer)},
        tags=['Signup Flow']
    )
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        
        if serializer.is_valid():
            phone_number = serializer.validated_data["phone_number"]
            
            # Check if user already exists
            if User.objects.filter(phone_number=phone_number).exists():
                return Response({"message": "User already exists!"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate a random 6-digit OTP
            otp = str(random.randint(100000, 999999))
            
            # Twilio client
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            
            message_body = f"{settings.TWILIO_MESSAGE_PART1}{otp}. {settings.TWILIO_MESSAGE_PART2}"
            
            try:
                # Send SMS
                client.messages.create(
                    body=message_body,
                    from_=settings.TWILIO_SMS_FROM_NUMBER,
                    to='+923244471192'
                )
                
                # Store OTP temporarily
                OTP_STORAGE[phone_number] = otp
                
                return Response({
                    "message": "OTP sent successfully!",
                    "otp": otp  # Returning OTP in response (for testing, remove in production)
                }, status=status.HTTP_200_OK)
            
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

















































# Temporary OTP storage (Use Redis or a database in production)
OTP_STORAGE = {}

class SendOTPView(APIView):
    """
    Send OTP via Twilio to the given phone number.
    """

    @swagger_auto_schema(
        request_body=SendOTPSerializer,
        responses={200: openapi.Response("OTP sent successfully!", SendOTPSerializer)},
        tags=['Signup Flow']
    )
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)

        if serializer.is_valid():
            phone_number = serializer.validated_data["phone_number"]

            # Generate a random 6-digit OTP
            otp = str(random.randint(100000, 999999))

            # Twilio client
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

            message_body = f"{settings.TWILIO_MESSAGE_PART1}{otp}. {settings.TWILIO_MESSAGE_PART2}"

            try:
                # Send SMS
                client.messages.create(
                    body=message_body,
                    from_=settings.TWILIO_SMS_FROM_NUMBER,
                    to=phone_number
                )

                # Store OTP temporarily
                OTP_STORAGE[phone_number] = otp

                return Response({
                    "message": "OTP sent successfully!",
                    "otp": otp  # Returning OTP in response
                }, status=status.HTTP_200_OK)

            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    """
    Verify the OTP received on the given phone number.
    """

    @swagger_auto_schema(
        request_body=VerifyOTPSerializer,
        responses={200: openapi.Response("OTP verified successfully!")},tags=['Signup Flow']
    )
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)

        if serializer.is_valid():
            phone_number = serializer.validated_data["phone_number"]
            otp = serializer.validated_data["otp"]

            # Check if OTP is valid
            if OTP_STORAGE.get(phone_number) == otp:
                # OTP is correct, remove it from storage
                del OTP_STORAGE[phone_number]
                return Response({"message": "OTP verified successfully!"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendEmailView(GenericAPIView):
    serializer_class = EmailSerializer

    @swagger_auto_schema(
        request_body=EmailSerializer,
        responses={200: "Email sent successfully!", 400: "Validation Error", 500: "Internal Server Error"},
        
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            subject = serializer.validated_data['subject']
            body = serializer.validated_data['body']
            to_email = serializer.validated_data['to_email']

            try:
                send_mail(subject, body, 'your_email@example.com', [to_email])
                return Response({"message": "Email sent successfully!"}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# class RegisterUserView(APIView):
#     """
#     API endpoint for user registration.
#     """
    
#     @swagger_auto_schema(
#         operation_description="Register a new user",
#         request_body=RegisterUserSerializer,
#         responses={
#             201: openapi.Response(
#                 "User successfully registered",
#                 openapi.Schema(
#                     type=openapi.TYPE_OBJECT,
#                     properties={
#                         'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
#                         'message': openapi.Schema(type=openapi.TYPE_STRING),
#                         'tokens': openapi.Schema(
#                             type=openapi.TYPE_OBJECT,
#                             properties={
#                                 'refresh': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'access': openapi.Schema(type=openapi.TYPE_STRING)
#                             }
#                         ),
#                         'user': openapi.Schema(
#                             type=openapi.TYPE_OBJECT,
#                             properties={
#                                 'id': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'full_name': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'first_name': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'last_name': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'email': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'country_code': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'profile_picture': openapi.Schema(type=openapi.TYPE_STRING, description="URL of the profile picture")
#                             }
#                         )
#                     }
#                 )
#             ),
#             400: openapi.Response("Bad request, validation errors"),
#         },
#         tags=['Signup Flow']
#     )
#     def post(self, request):
#         serializer = RegisterUserSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save()
#             # Assuming you want to return JWT tokens
#             tokens = serializer.get_tokens(user)
            
#             return Response({
#                 "success": True,
#                 "message": "User registered successfully",
#                 "tokens": tokens,
#                 "user": RegisterUserSerializer(user).data  # Include user data in the response
#             }, status=status.HTTP_201_CREATED)
        
#         return Response({
#             "success": False,
#             "errors": serializer.errors
#         }, status=status.HTTP_400_BAD_REQUEST)


# class RegisterUserView(APIView):
#     """
#     API endpoint for user registration.
#     """
    
#     @swagger_auto_schema(
#         operation_description="Register a new user",
#         request_body=RegisterUserSerializer,
#         responses={
#             201: openapi.Response(
#                 "User successfully registered",
#                 openapi.Schema(
#                     type=openapi.TYPE_OBJECT,
#                     properties={
#                         'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
#                         'message': openapi.Schema(type=openapi.TYPE_STRING),
#                         'tokens': openapi.Schema(
#                             type=openapi.TYPE_OBJECT,
#                             properties={
#                                 'refresh': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'access': openapi.Schema(type=openapi.TYPE_STRING)
#                             }
#                         ),
#                         'user': openapi.Schema(
#                             type=openapi.TYPE_OBJECT,
#                             properties={
#                                 'id': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'full_name': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'first_name': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'last_name': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'email': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'country_code': openapi.Schema(type=openapi.TYPE_STRING),
#                                 'profile_pic_url': openapi.Schema(type=openapi.TYPE_STRING, description="URL of the profile picture")  # Updated field name
#                             }
#                         )
#                     }
#                 )
#             ),
#             400: openapi.Response("Bad request, validation errors"),
#         },
#         tags=['Signup Flow']
#     )
#     def post(self, request):
#         serializer = RegisterUserSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save()
#             # Generate JWT tokens
#             tokens = serializer.get_tokens(user)
            
#             return Response({
#                 "success": True,
#                 "message": "User registered successfully",
#                 "tokens": tokens,
#                 "user": RegisterUserSerializer(user).data  # Include user data in the response
#             }, status=status.HTTP_201_CREATED)
        
#         return Response({
#             "success": False,
#             "errors": serializer.errors
#         }, status=status.HTTP_400_BAD_REQUEST)


# from django.contrib.auth import get_user_model
# from rest_framework_simplejwt.tokens import RefreshToken

# User = get_user_model()
 # Import your serializer

User = get_user_model()


from rest_framework.response import Response
from rest_framework import status
from drf_yasg import openapi

class RegisterUserView(APIView):
    """
    API endpoint for user registration and JWT validation.
    """

    @swagger_auto_schema(
        operation_description="Register a new user",
        request_body=RegisterUserSerializer,
        responses={
            201: openapi.Response(
                "User successfully registered",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'tokens': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                                'access': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        ),
                        'user': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'full_name': openapi.Schema(type=openapi.TYPE_STRING),
                                'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                                'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                                'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                                'full_number': openapi.Schema(type=openapi.TYPE_STRING),
                                'email': openapi.Schema(type=openapi.TYPE_STRING),
                                'is_admin': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'is_email_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'is_approved': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'is_deleted': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'is_mute': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'is_stripe_connect': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'device_type': openapi.Schema(type=openapi.TYPE_STRING),
                                'device_token': openapi.Schema(type=openapi.TYPE_STRING),
                                'country_code': openapi.Schema(type=openapi.TYPE_STRING),
                                'country_iso': openapi.Schema(type=openapi.TYPE_STRING),
                                'country': openapi.Schema(type=openapi.TYPE_STRING),
                                'city': openapi.Schema(type=openapi.TYPE_STRING),
                                'state': openapi.Schema(type=openapi.TYPE_STRING),
                                'postal_code': openapi.Schema(type=openapi.TYPE_STRING),
                                'address': openapi.Schema(type=openapi.TYPE_STRING),
                                'bio': openapi.Schema(type=openapi.TYPE_STRING),
                                'badge': openapi.Schema(type=openapi.TYPE_STRING),
                                'user_type': openapi.Schema(type=openapi.TYPE_STRING),
                                'profile_pic_url': openapi.Schema(type=openapi.TYPE_STRING),
                                'location': openapi.Schema(type=openapi.TYPE_STRING),
                                'default_location': openapi.Schema(type=openapi.TYPE_STRING),
                                'total_number_of_rating': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'average_rating': openapi.Schema(type=openapi.TYPE_NUMBER),
                                'total_rating': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'driver_total_number_of_rating': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'driver_average_rating': openapi.Schema(type=openapi.TYPE_NUMBER),
                                'driver_total_rating': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'document_uploaded': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'access_token': openapi.Schema(type=openapi.TYPE_STRING),
                                'setting_applied': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'discovery_radius': openapi.Schema(type=openapi.TYPE_NUMBER),
                                'no_delivery': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'recent_orders': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING)),
                                'nearest_orders': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING)),
                                'highest_earning_orders': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING)),
                                'least_earning_orders': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING)),
                                'filter_type': openapi.Schema(type=openapi.TYPE_STRING),
                                'email_id': openapi.Schema(type=openapi.TYPE_STRING),
                                'created_at': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME),
                                'updated_at': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME),
                            }
                        ),
                    }
                )
            ),
            400: openapi.Response("Bad request, validation errors"),
        },
        tags=['Signup Flow']
    )
    def post(self, request):
        """Register a new user and generate JWT tokens."""
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            # Retrieve the user from the database using email
            email = serializer.validated_data.get("email")
            user = User.objects.filter(email=email).first()

            if user is None:
                print("❌ Error: User not found after creation!")  # Debugging print
                return Response({
                    "success": False,
                    "message": "User creation failed"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Serialize the user profile
            user_data = UserProfileSerializer(user).data

            print(f"✅ User registered: ID={user.id}, Email={user.email}")  # Debugging print

            return Response({
                "success": True,
                "message": "User registered successfully",
                "tokens": {
                    "refresh": str(refresh),
                    "access": access_token
                },
                "user": user_data  # Include serialized user data here
            }, status=status.HTTP_201_CREATED)

        print(f"❌ Registration failed: {serializer.errors}")  # Debugging print
        return Response({
            "success": False,
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class ValidateJWTView(APIView):
    """
    API endpoint to validate JWT token.
    """

    authentication_classes = [JWTAuthentication]  # Enables JWT Authentication
    permission_classes = [IsAuthenticated]  # Requires authentication

    @swagger_auto_schema(
        operation_description="Validate JWT token and return authenticated user info",
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Bearer <access_token>",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                "Token is valid",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'user': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            401: openapi.Response("Unauthorized - Token is invalid or expired"),
        },
        tags=['Authentication']
    )
    def get(self, request):
        """
        Validate JWT token and return the authenticated user.
        """
        return Response({
            "message": "Token is valid",
            "user": {
                "id": request.user.id,
                "email": request.user.email,
                "full_name": request.user.get_full_name(),
            }
        }, status=status.HTTP_200_OK)

























# class UserDetailViewnew(APIView):
#     # Specify that the view should use 'custom_id' for lookups
#     lookup_field = 'custom_id'

#     def get(self, request, custom_id):
#         try:
#             # Retrieve the user using the custom_id field
#             user = User.objects.get(custom_id=custom_id)
#             serializer = UserSerializer(user)
#             response_data = {
#                 "success": True,
#                 "message": "User data retrieved successfully.",
#                 "data": serializer.data
#             }
#             return Response(response_data, status=status.HTTP_200_OK)
#         except User.DoesNotExist:
#             response_data = {
#                 "success": False,
#                 "message": "User not found.",
#                 "data": None
#             }
#             return Response(response_data, status=status.HTTP_404_NOT_FOUND)
class SocialLoginOrRegisterView(APIView):
    def post(self, request):
        serializer = SocialRegistrationSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            if not user.id:
                # If the user doesn't have an ID, retrieve by email
                email = request.data.get('email')  # Get email from request
                user_by_email = get_object_or_404(User, email=email)
                user = user_by_email  # Use the user retrieved by email

            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Determine if the user was newly created or logged in
            if user.pk:  # If user exists (logged in)
                message = 'User logged in successfully.'
            else:  # If user is newly created (registered)
                message = 'User registered successfully.'

            return Response({
                'success': True,
                'message': message,
                'data': {
                    'refresh': str(refresh),
                    'access': access_token,
                    'id': user.id,
                    'user': serializer.data
                }
            }, status=status.HTTP_200_OK)

        return Response({
            'success': False,
            'message': 'Failed to register or log in user.',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)




class ResendOTPView(APIView):
    def post(self, request, format=None):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # Generate 4-digit API code
        api_code = get_random_string(length=4, allowed_chars='0123456789')

        # Update the user's OTP code
        user.otp_code = api_code
        user.save()

        # Send email to the user
        subject = 'Your 4-digit API'
        message = f'Your 4-digit API is: {api_code}'
        from_email = 'muhammadobaidullah1122@gmail.com'  # Update with your email
        to_email = user.email
        try:
            send_mail(subject, message, from_email, [to_email])
            return Response({'success': True, 'message': 'OTP resent successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': 'Failed to resend OTP email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
def generate_random_password(length=8):
    # Generate a random 8-digit password
    return ''.join(random.choices(string.digits, k=length))

@api_view(['POST'])
def set_new_password(request):
    if request.method == 'POST':
        email = request.data.get('email')

        # Retrieve the user object from the database
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'No user found with this email.'}, status=400)

        # Generate a new random password
        new_password = generate_random_password()

        # Hash the new password before saving it
        hashed_password = make_password(new_password)

        # Update the user's password in the database
        user.password = hashed_password
        user.save()

        # Send the new password to the user's email
        subject = 'Your New Password'
        message = f'Your new password is: {new_password}'
        from_email = 'your@example.com'
        to_email = email
        try:
            send_mail(subject, message, from_email, [to_email])
            return JsonResponse({'success': True, 'message': 'Password  successfully  sent to the registered  email.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)
    else:
        return JsonResponse({'success': False, 'message': 'Method not allowed.'}, status=405)




class UserDeleteAPIView(APIView):
    def delete(self, request, custom_id, format=None):
        try:
            user = User.objects.get(id=custom_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # Log user details before deletion
        print(f"Deleting user: {user.username} (Custom ID: {user.id})")

        # Delete the user
        user.delete()

        return Response({'success': True, 'message': 'User deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
def send_verification_email(user_id):
    """
    Send a verification email containing a 4-digit code to the user's email address
    and update the user's OTP field with the generated code.

    Args:
        user_id (int): ID of the user to send the verification email to.

    Returns:
        bool: True if email is sent successfully and user's OTP field is updated, False otherwise.
    """
    try:
        # Retrieve user object using user ID
        user = User.objects.get(id=user_id)

        # Generate a 4-digit verification code
        verification_code = get_random_string(length=4, allowed_chars='0123456789')

        # Compose email details
        subject = 'Your 4-digit Verification Code'
        message = f'Your 4-digit verification code is: {verification_code}'
        from_email = "muhammadobaidullah1122@gmail.com"
        to_email = user.email

        # Send email
        send_mail(subject, message, from_email, [to_email])

        # Update user's OTP field with the generated verification code
        user.otp_code = verification_code
        user.save()

        return True
    except User.DoesNotExist:
        print(f"User with ID {user_id} does not exist")
        return False
    except Exception as e:
        print(f"Failed to send verification email: {e}")
        return False
# Generate Token Manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }
class PasswordResetAPIView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user  # Assuming the user is authenticated and making the request
        user.password = make_password(serializer.validated_data['password'])
        user.save()

        return Response({'success': True, 'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
@api_view(['GET'])
def list_users(request):
    # Query all users from the database
    all_users = User.objects.all()

    # Serialize the queryset of users
    serializer = UserProfileSerializer(all_users, many=True)

    # Return serialized data in the response
    return Response(serializer.data)
# from users.utils import get_tokens_for_user
class UserUpdateAPIView(APIView):
    def post(self, request, custom_id, format=None):
        try:
            user = User.objects.get(id=custom_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # Serialize data
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'success': True, 'message': 'User data updated successfully'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class UserDetailView(APIView):
    # Explicitly tell DRF to look for custom_id instead of the default id field
    lookup_field = 'custom_id'

    def get(self, request, custom_id):
        try:
            # Fetch the user by custom_id
            user = User.objects.get(custom_id=custom_id)
            serializer = UserSerializer(user)

            # Structure the response
            response_data = {
                "success": True,
                "message": "User data retrieved successfully.",
                "data": serializer.data
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            response_data = {
                "success": False,
                "message": "User not found.",
                "data": None
            }
            return Response(response_data, status=status.HTTP_404_NOT_FOUND)
class UserDetailViewnew(APIView):
    # Explicitly tell DRF to look for custom_id instead of the default id field
    lookup_field = 'custom_id'

    def get(self, request, custom_id):
        try:
            # Fetch the user by custom_id
            user = User.objects.get(id=custom_id)
            serializer = UserSerializer(user)

            # Structure the response
            response_data = {
                "success": True,
                "message": "User data retrieved successfully.",
                "data": serializer.data
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            response_data = {
                "success": False,
                "message": "User not found.",
                "data": None
            }
            return Response(response_data, status=status.HTTP_404_NOT_FOUND)
# class UserRegistrationView(APIView):
#     renderer_classes = [UserRenderer]

#     def post(self, request, format=None):
#         serializer = UserRegistrationSerializer(data=request.data)

#         try:
#             serializer.is_valid(raise_exception=True)
#         except ValidationError as e:
#             error_detail = e.detail
#             if 'email' in error_detail:
#                 return Response({'success': False, 'error': "User with this Email already exists."}, status=status.HTTP_400_BAD_REQUEST)
#             else:
#                 return Response({'success': False, 'error': error_detail}, status=status.HTTP_400_BAD_REQUEST)

#         to_email = request.data.get('email')

#         # Save user data
#         user = serializer.save()
#         print(f"User {to_email} saved successfully.")

#         # Generate 4-digit API code
#         api_code = get_random_string(length=4, allowed_chars='0123456789')
#         # print(f"Generated API code: {request.data.email}")

#         # Send email to the user
#         subject = 'Your 4-digit API'
#         message = f'Your 4-digit API is: {api_code}'
#         from_email = 'muhammadobaidullah1122@gmail.com'  # Update with your email
#         to_email = to_email
#         try:
#             send_mail(subject, message, from_email, [to_email])
#             print(f"OTP email sent to {to_email}.")
#         except Exception as e:
#             # If sending email fails, return failure response
#             print(f"Failed to send OTP email to {to_email}. Error: {e}")
#             return Response({'success': False, 'message': 'Failed to send OTP email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#         return Response({'success': True, 'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)
# class UserRegistrationView(APIView):
#     renderer_classes = [UserRenderer]

#     def post(self, request, format=None):
#         serializer = UserRegistrationSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         to_email=request.data.get('email')

#         # Save user data
#         # user = serializer.save()
#         print(f"User {to_email} saved successfully.")

#         # Generate 4-digit API code
#         api_code = get_random_string(length=4, allowed_chars='0123456789')
#         # print(f"Generated API code: {request.data.email}")

#         # Send email to the user
#         subject = 'Your 4-digit API'
#         message = f'Your 4-digit API is: {api_code}'
#         from_email = 'muhammadobaidullah1122@gmail.com'  # Update with your email
#         to_email = to_email
#         try:
#             send_mail(subject, message, from_email, [to_email])
#             print(f"OTP email sent to {to_email}.")
#         except Exception as e:
#             # If sending email fails, return failure response
#             print(f"Failed to send OTP email to {to_email}. Error: {e}")
#             return Response({'success': False, 'message': 'Failed to send OTP email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Update OTP code in the user model
        # otp_code = api_code
        # user = serializer.save(otp_code=api_code)

        # # Get tokens for user
        # token = get_tokens_for_user(user)
        # print(f"Tokens generated for user {user.username}.")

        # Response indicating success and message
        # return Response({'success': True, 'message': 'User registered successfully. OTP sent to your email'}, status=status.HTTP_201_CREATED)
# class UserRegistrationView(APIView):
#     renderer_classes = [UserRenderer]

#     def post(self, request, format=None):
#         serializer = UserRegistrationSerializer(data=request.data)

#         try:
#             serializer.is_valid(raise_exception=True)
#         except ValidationError as e:
#             error_detail = e.detail
#             if 'email' in error_detail:
#                 return Response({'success': False, 'error': "User with this Email already exists."}, status=status.HTTP_400_BAD_REQUEST)
#             else:
#                 return Response({'success': False, 'error': error_detail}, status=status.HTTP_400_BAD_REQUEST)

#         to_email = request.data.get('email')

#         # Generate 4-digit API code
#         api_code = get_random_string(length=4, allowed_chars='0123456789')
#         otp_code = api_code

#         # Save user data with the OTP code
#         user = serializer.save(otp_code=otp_code)
#         print(f"User {to_email} saved successfully with OTP code {otp_code}.")

#         # Send email to the user
#         subject = 'Your 4-digit API'
#         message = f'Your 4-digit API is: {api_code}'
#         from_email = 'muhammadobaidullah1122@gmail.com'  # Update with your email
#         try:
#             send_mail(subject, message, from_email, [to_email])
#             print(f"OTP email sent to {to_email}.")
#         except Exception as e:
#             # If sending email fails, return failure response
#             print(f"Failed to send OTP email to {to_email}. Error: {e}")
#             return Response({'success': False, 'message': 'Failed to send OTP email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#         # Get tokens for user
#         token = get_tokens_for_user(user)
#         print(f"Tokens generated for user {user.username}.")

#         # Response indicating success and message
#         return Response({
#             'success': True,
#             'message': 'User registered successfully. OTP sent to your email.',

#         }, status=status.HTTP_201_CREATED)
        

class UserRegistrationView(APIView):
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            error_detail = e.detail
            if 'email' in error_detail:
                return Response({'success': False, 'error': "User with this Email already exists."}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'success': False, 'error': error_detail}, status=status.HTTP_400_BAD_REQUEST)

        to_email = request.data.get('email')
        to_contact = request.data.get('contact')

        if not to_contact:
            return Response({'success': False, 'error': 'Phone number is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate 5-digit OTP
        otp_code = get_random_string(length=5, allowed_chars='0123456789')

        # Save user data with the OTP code
        user = serializer.save(otp_code=otp_code)
        print(f"User {to_email} saved successfully with OTP code {otp_code}.")

        # Send Email OTP
        subject = 'Your 5-digit API OTP'
        message = f'{settings.TWILIO_MESSAGE_PART1}{otp_code}. {settings.TWILIO_MESSAGE_PART2}'
        from_email = 'muhammadobaidullah1122@gmail.com'  # Update with your email
        try:
            send_mail(subject, message, from_email, [to_email])
            print(f"OTP email sent to {to_email}.")
        except Exception as e:
            print(f"Failed to send OTP email to {to_email}. Error: {e}")
            return Response({'success': False, 'message': 'Failed to send OTP email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Send SMS OTP
        try:
            twilio_client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            twilio_client.messages.create(
                body=f'{settings.TWILIO_MESSAGE_PART1}{otp_code}. {settings.TWILIO_MESSAGE_PART2}',
                from_=settings.TWILIO_SMS_FROM_NUMBER,
                to=to_contact if to_contact.startswith('+') else f'+{to_contact}'  # Ensure E.164 format
            )
            print(f"OTP SMS sent to {to_contact}.")
        except Exception as e:
            print(f"Failed to send OTP SMS to {to_contact}. Error: {e}")
            return Response({'success': False, 'message': 'Failed to send OTP SMS'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Response indicating success
        return Response({
            'success': True,
            'message': 'User registered successfully. OTP sent to your email and phone.',
        }, status=status.HTTP_201_CREATED)

class VerifyOTP(APIView):
    def post(self, request):
        code = request.data.get('code')

        if not code:
            return Response({'success': False, 'error': 'Verification code is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve the user based on the provided OTP code
            user = User.objects.get(otp_code=code)
        except User.DoesNotExist:
            return Response({'success': False, 'error': 'Please enter correct OTP code. Thank you'}, status=status.HTTP_404_NOT_FOUND)

        # Now you have the user based on the OTP code
        # Proceed with your verification process

        # Update the 'verify' field to True
        user.verify = True
        user.save()

        # Generate JWT token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Modify response message to include user ID
        return Response({
            'success': True,
            'message': 'Verification successful',
            'token': access_token,
            'refresh': str(refresh),
            'user_id': user.id  # Include user ID in the response
        }, status=status.HTTP_200_OK)
# class UserLoginView(APIView):
#   renderer_classes = [UserRenderer]
#   def post(self, request, format=None):
#     serializer = UserLoginSerializer(data=request.data)
#     serializer.is_valid(raise_exception=True)
#     email = serializer.data.get('email')
#     password = serializer.data.get('password')
#     user = authenticate(email=email, password=password)
#     if user is not None:
#       token = get_tokens_for_user(user)
#       return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
#     else:
#       return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)


# class UserLoginView(APIView):
#     def post(self, request, format=None):
#         serializer = UserLoginSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         email = serializer.data.get('email')
#         password = serializer.data.get('password')
#         user = authenticate(email=email, password=password)
#         if user is not None:
#             refresh = RefreshToken.for_user(user)
#             token = str(refresh.access_token)
#             profile_serializer = UserProfileSerializer(user)
#             return Response({'success': True, 'id': user.id, 'token': token, 'profile': profile_serializer.data}, status=status.HTTP_200_OK)
#         else:
#             return Response({'success': False, 'errors': {'non_field_errors': ['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)
class UpdatePasswordViewnew(APIView):
    def post(self, request):
        email = request.data.get("email")
        new_password = request.data.get("new_password")

        if not email or not new_password:
            return Response(
                {"error": "Email and new password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
            user.set_password(new_password)  # Use set_password to properly hash the password
            user.save()
            return Response(
                {"success": "Password updated successfully."},
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return Response(
                {"error": "User with this email does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )
class UseradminLoginView(APIView):
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')

        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Email or Password is not valid.'
            }, status=status.HTTP_200_OK)

        # Check if user is verified



        # Authenticate user
        user = authenticate(username=email, password=password)  # Use email as username for authentication

        if user is not None:
            # Check if the user is an admin
            if user.user_type != 'admin':
                return Response({
                    'success': False,
                    'message': 'Access denied. Only admin users can log in here.'
                }, status=status.HTTP_200_OK)

            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            token = str(refresh.access_token)
            profile_serializer = UserProfileSerializer(user)  # Serialize User instance if needed

            return Response({
                'success': True,
                'is_verified': user.verify,
                'id': user.id,
                'token': token,
                'profile': profile_serializer.data if profile_serializer else None,
                'message': 'Login successful.'
            }, status=status.HTTP_200_OK)

        else:
            return Response({
                'success': False,
                'message': 'Email or Password is not valid.'
            }, status=status.HTTP_200_OK)
class UserLoginView(APIView):
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')

        # Check if user exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Email or Password is not valid.'
            }, status=status.HTTP_200_OK)

        # Check if user is verified
        if not user.verify:
            return Response({
                'success': False,
                'is_verified':user.verify,
                'message': 'Account is not verified. Please verify your email.'
            }, status=status.HTTP_200_OK)
        if not user.is_active:
            return Response({
                'success': False,
                'is_verified':user.verify,
                'is_active':user.is_active,
                'message': 'Account has been deactivated by Admin'
            }, status=status.HTTP_200_OK)
        # Authenticate user
        user = authenticate(username=email, password=password)  # Use email as username for authentication

        if user is not None:
            refresh = RefreshToken.for_user(user)
            token = str(refresh.access_token)
            profile_serializer = UserProfileSerializer(user)  # Serialize User instance if needed
            return Response({
                'success': True,
                'is_verified':user.verify,
                'id': user.id,
                'token': token,
                'profile': profile_serializer.data if profile_serializer else None,  # Include profile data if needed
                'message': 'Login successful.'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'success': False,
                'message': 'Email or Password is not valid.'
            }, status=status.HTTP_200_OK)

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        try:
            serializer = UserProfileSerializer(request.user)
            return Response({
                "success": True,
                "message": "User profile retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "message": f"An error occurred: {str(e)}",
                "data": {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class UserChangePasswordView(APIView):
    def post(self, request, custom_id, format=None):
        try:
            # Retrieve the user based on the custom_id
            user = User.objects.get(id=custom_id)
        except User.DoesNotExist:
            # If user does not exist, return error response
            return Response({'success': False, 'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # Initialize the serializer with user context and request data
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': user})

        # Validate the serializer data
        if serializer.is_valid():
            # Save the validated serializer (which updates the user's password)
            serializer.save()
            # Return success response if password changed successfully
            return Response({'success': True, 'message': 'Password changed successfully'}, status=status.HTTP_200_OK)

        # Return error response if serializer data is invalid
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# class UserChangePasswordView(APIView):
#   renderer_classes = [UserRenderer]
#   permission_classes = [IsAuthenticated]
#   def post(self, request, format=None):
#     serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
#     serializer.is_valid(raise_exception=True)
#     return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class SendPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)


class DriverListAPIView(APIView):
    def get(self, request):
        drivers = User.objects.filter(role='Driver')
        serializer = DriverSerializer(drivers, many=True)
        return Response(serializer.data)

@api_view(['POST'])
def set_user_deleted(request, user_id):
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    user.is_deleted = True
    user.save()

    return Response({'message': f'Your account has been deleted'})