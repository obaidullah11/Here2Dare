from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import generics
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import get_object_or_404
# from users.serializers import phoneloginSerializer,UserUpdateSerializer,SendPasswordResetEmailSerializer,DriverSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserRegistrationSerializer
from.serializers import *
from users.renderers import UserRenderer
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
import random
from rest_framework.exceptions import ValidationError
import string
from django.conf import settings
from twilio.rest import Client
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import json
from rest_framework.generics import GenericAPIView
from drf_yasg import openapi
from django.contrib.auth import get_user_model
from drf_yasg.utils import swagger_auto_schema
from rest_framework import serializers, status
 # Adjust to your actual User model
from django.core.validators import EmailValidator
from .serializers import FileUploadSerializern
from rest_framework.parsers import MultiPartParser, FormParser
from PIL import Image
from io import BytesIO
from django.core.files.uploadedfile import InMemoryUploadedFile











User = get_user_model()


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





# api to check phone number




class CheckPhoneNumberView(APIView):
    """
    Check if a phone number exists in the database and return user data if found.
    """
    
    @swagger_auto_schema(
        request_body=phoneloginSerializer,
        responses={200: openapi.Response("Phone number checked successfully!", SendOTPSerializer)},
        tags=['Login Flow']
    )
    def post(self, request):
        serializer = phoneloginSerializer(data=request.data)
        
        if serializer.is_valid():
            phone_number = serializer.validated_data["phone_number"]
            user = User.objects.filter(phone_number=phone_number).first()
            
            if user:
                user_data = {
                    "id": user.id,
                    "phone_number": user.phone_number,
                    "first_name": user.first_name if hasattr(user, 'first_name') else None,
                    "last_name": user.last_name if hasattr(user, 'last_name') else None,
                }
                return Response({"success": True, "message": "User exists!", "data": user_data}, status=status.HTTP_200_OK)
            else:
                return Response({"success": False, "message": "User does not exist.", "data": {}}, status=status.HTTP_404_NOT_FOUND)
        
        return Response({"success": False, "message": "Invalid data", "data": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)





# api to login user using phonenumber and password



class PhoneLoginAPIView(APIView):
    @swagger_auto_schema(
        operation_description="Login with phone number and password",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description="User's phone number"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="User's password"),
            },
            required=['phone_number', 'password'],
        ),
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Login successful", 
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Indicates if the login was successful"),
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description="Message related to the response"),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'refresh': openapi.Schema(type=openapi.TYPE_STRING, description="Refresh token"),
                                'access': openapi.Schema(type=openapi.TYPE_STRING, description="Access token"),
                                'user': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'id': openapi.Schema(type=openapi.TYPE_INTEGER, description="User ID"),
                                        'full_name': openapi.Schema(type=openapi.TYPE_STRING, description="Full name of the user"),
                                        'first_name': openapi.Schema(type=openapi.TYPE_STRING, description="User's first name"),
                                        'last_name': openapi.Schema(type=openapi.TYPE_STRING, description="User's last name"),
                                        'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description="User's phone number"),
                                        'full_number': openapi.Schema(type=openapi.TYPE_STRING, description="Full phone number"),
                                        'email': openapi.Schema(type=openapi.TYPE_STRING, description="User's email"),
                                        'is_admin': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="If the user is an admin"),
                                        'is_email_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="If the email is verified"),
                                        'is_approved': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="If the user is approved"),
                                        'is_deleted': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="If the user is deleted"),
                                        'is_mute': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="If the user is muted"),
                                        'is_stripe_connect': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="If Stripe is connected"),
                                        'device_type': openapi.Schema(type=openapi.TYPE_STRING, description="Type of device used"),
                                        'device_token': openapi.Schema(type=openapi.TYPE_STRING, description="Device token"),
                                        'country_code': openapi.Schema(type=openapi.TYPE_STRING, description="Country code"),
                                        'country_iso': openapi.Schema(type=openapi.TYPE_STRING, description="Country ISO code"),
                                        'country': openapi.Schema(type=openapi.TYPE_STRING, description="Country name"),
                                        'city': openapi.Schema(type=openapi.TYPE_STRING, description="City of the user"),
                                        'state': openapi.Schema(type=openapi.TYPE_STRING, description="State of the user"),
                                        'postal_code': openapi.Schema(type=openapi.TYPE_STRING, description="Postal code"),
                                        'address': openapi.Schema(type=openapi.TYPE_STRING, description="User's address"),
                                        'bio': openapi.Schema(type=openapi.TYPE_STRING, description="User's bio"),
                                        'badge': openapi.Schema(type=openapi.TYPE_STRING, description="User's badge"),
                                        'user_type': openapi.Schema(type=openapi.TYPE_STRING, description="Type of user"),
                                        'profile_pic_url': openapi.Schema(type=openapi.TYPE_STRING, description="Profile picture URL"),
                                        'location': openapi.Schema(type=openapi.TYPE_STRING, description="Location of the user"),
                                        'default_location': openapi.Schema(type=openapi.TYPE_STRING, description="Default location"),
                                        'total_number_of_rating': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of ratings"),
                                        'average_rating': openapi.Schema(type=openapi.TYPE_NUMBER, description="Average rating"),
                                        'total_rating': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total rating"),
                                        'driver_total_number_of_rating': openapi.Schema(type=openapi.TYPE_INTEGER, description="Driver's total number of ratings"),
                                        'driver_average_rating': openapi.Schema(type=openapi.TYPE_NUMBER, description="Driver's average rating"),
                                        'driver_total_rating': openapi.Schema(type=openapi.TYPE_INTEGER, description="Driver's total rating"),
                                        'document_uploaded': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="If the document is uploaded"),
                                        'access_token': openapi.Schema(type=openapi.TYPE_STRING, description="Access token"),
                                        'setting_applied': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="If settings have been applied"),
                                        'discovery_radius': openapi.Schema(type=openapi.TYPE_NUMBER, description="Discovery radius"),
                                        'no_delivery': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="If no delivery is available"),
                                        'recent_orders': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description="List of recent orders"),
                                        'nearest_orders': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description="List of nearest orders"),
                                        'highest_earning_orders': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description="List of highest earning orders"),
                                        'least_earning_orders': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description="List of least earning orders"),
                                        'filter_type': openapi.Schema(type=openapi.TYPE_STRING, description="Filter type"),
                                        'email_id': openapi.Schema(type=openapi.TYPE_STRING, description="Email ID"),
                                        'created_at': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME, description="User's account creation date"),
                                        'updated_at': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME, description="User's account last update date"),
                                    }
                                ),
                            }
                        ),
                    }
                )
            ),
            status.HTTP_400_BAD_REQUEST: "Phone number and password are required.",
            status.HTTP_401_UNAUTHORIZED: "Invalid phone number or password."
        },
        tags=['Login Flow']
    )
    def post(self, request):
        phone_number = request.data.get("phone_number")
        password = request.data.get("password")
        
        if not phone_number or not password:
            return Response({
                "success": False,
                "message": "Phone number and password are required.",
                "data": None
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return Response({
                "success": False,
                "message": "Invalid phone number or password.",
                "data": None
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        user = authenticate(username=user.email, password=password)
        if user is None:
            return Response({
                "success": False,
                "message": "Invalid phone number or password.",
                "data": None
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        refresh = RefreshToken.for_user(user)

        # Serialize user data
        user_data = UserProfileSerializer(user).data
        
        return Response({
            "success": True,
            "message": "Login successful",
            "data": {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": user_data,
            }
        }, status=status.HTTP_200_OK)




# api to get user detail using JWT




class UserProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get authenticated user profile",
        responses={
            200: openapi.Response(
                description="User Profile Response",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "success": openapi.Schema(type=openapi.TYPE_BOOLEAN, example=True),
                        "message": openapi.Schema(type=openapi.TYPE_STRING, example="User profile fetched successfully"),
                        "data": openapi.Schema(type=openapi.TYPE_OBJECT)  # Data will be the serialized user object
                    }
                )
            )
        },
        tags=['Login Flow']
    )
    def get(self, request):
        user = request.user
        serializer = profileUserSerializer(user)

        response_data = {
            "success": True,
            "message": "User profile fetched successfully",
            "data": serializer.data
        }

        return Response(response_data, status=status.HTTP_200_OK)





# api to update user record


















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
#


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


