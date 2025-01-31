from rest_framework import serializers
from django.contrib.auth import authenticate
from users.models import User,DocumentVerification
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from users.utils import Util
from rest_framework_simplejwt.tokens import RefreshToken



from rest_framework import serializers


from rest_framework import serializers
from .models import User, DocumentVerification

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id', 'full_name', 'first_name', 'last_name', 'phone_number', 'full_number', 'email', 
            'is_admin', 'is_email_verified', 'is_approved', 'is_deleted', 'is_mute', 'is_stripe_connect', 
            'device_type', 'device_token', 'country_code', 'country_iso', 'country', 'city', 'state', 
            'postal_code', 'address', 'bio', 'badge', 'user_type', 'profile_pic_url', 'location', 
            'default_location', 'total_number_of_rating', 'average_rating', 'total_rating', 
            'driver_total_number_of_rating', 'driver_average_rating', 'driver_total_rating', 'document_uploaded', 
            'access_token', 'setting_applied', 'discovery_radius', 'no_delivery', 'recent_orders', 
            'nearest_orders', 'highest_earning_orders', 'least_earning_orders', 'filter_type', 'email_id', 
            'created_at', 'updated_at'
        )
    
    def update(self, instance, validated_data):
        # Update the instance with validated data
        instance.full_name = validated_data.get('full_name', instance.full_name)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.email = validated_data.get('email', instance.email)
        instance.is_admin = validated_data.get('is_admin', instance.is_admin)
        instance.is_email_verified = validated_data.get('is_email_verified', instance.is_email_verified)
        instance.is_approved = validated_data.get('is_approved', instance.is_approved)
        instance.is_deleted = validated_data.get('is_deleted', instance.is_deleted)
        instance.is_mute = validated_data.get('is_mute', instance.is_mute)
        instance.is_stripe_connect = validated_data.get('is_stripe_connect', instance.is_stripe_connect)
        instance.device_type = validated_data.get('device_type', instance.device_type)
        instance.device_token = validated_data.get('device_token', instance.device_token)
        instance.country_code = validated_data.get('country_code', instance.country_code)
        instance.country_iso = validated_data.get('country_iso', instance.country_iso)
        instance.country = validated_data.get('country', instance.country)
        instance.city = validated_data.get('city', instance.city)
        instance.state = validated_data.get('state', instance.state)
        instance.postal_code = validated_data.get('postal_code', instance.postal_code)
        instance.address = validated_data.get('address', instance.address)
        instance.bio = validated_data.get('bio', instance.bio)
        instance.badge = validated_data.get('badge', instance.badge)
        instance.user_type = validated_data.get('user_type', instance.user_type)
        instance.profile_pic_url = validated_data.get('profile_pic_url', instance.profile_pic_url)
        instance.location = validated_data.get('location', instance.location)
        instance.default_location = validated_data.get('default_location', instance.default_location)
        instance.total_number_of_rating = validated_data.get('total_number_of_rating', instance.total_number_of_rating)
        instance.average_rating = validated_data.get('average_rating', instance.average_rating)
        instance.total_rating = validated_data.get('total_rating', instance.total_rating)
        instance.driver_total_number_of_rating = validated_data.get('driver_total_number_of_rating', instance.driver_total_number_of_rating)
        instance.driver_average_rating = validated_data.get('driver_average_rating', instance.driver_average_rating)
        instance.driver_total_rating = validated_data.get('driver_total_rating', instance.driver_total_rating)
        instance.document_uploaded = validated_data.get('document_uploaded', instance.document_uploaded)
        instance.access_token = validated_data.get('access_token', instance.access_token)
        instance.setting_applied = validated_data.get('setting_applied', instance.setting_applied)
        instance.discovery_radius = validated_data.get('discovery_radius', instance.discovery_radius)
        instance.no_delivery = validated_data.get('no_delivery', instance.no_delivery)
        instance.recent_orders = validated_data.get('recent_orders', instance.recent_orders)
        instance.nearest_orders = validated_data.get('nearest_orders', instance.nearest_orders)
        instance.highest_earning_orders = validated_data.get('highest_earning_orders', instance.highest_earning_orders)
        instance.least_earning_orders = validated_data.get('least_earning_orders', instance.least_earning_orders)
        instance.filter_type = validated_data.get('filter_type', instance.filter_type)
        instance.email_id = validated_data.get('email_id', instance.email_id)
        instance.save()
        return instance

class DocumentVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentVerification
        fields = ('id', 'user', 'document_file', 'verification_status', 'verification_date')



      
class EmailExistenceCheckSerializer(serializers.Serializer):
    email = serializers.EmailField()

# Serializer for the response
class EmailExistenceCheckResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
    message = serializers.CharField()
    data = serializers.DictField()
class EmailSerializer(serializers.Serializer):
    subject = serializers.CharField(max_length=255)
    body = serializers.CharField()
    to_email = serializers.EmailField()


class SendOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)
class phoneloginSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)

    def validate_phone_number(self, value):
        if not User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("User with this phone number does not exist.")
        return value
class VerifyOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)
    otp = serializers.CharField(max_length=6)





from rest_framework import serializers
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework import serializers
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken

class RegisterUserSerializer(serializers.ModelSerializer):
    profile_pic_url = serializers.URLField(required=False, allow_null=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'country_code', 'password', 'profile_pic_url']

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user

    def to_representation(self, instance):
        # Get the original user data
        user_data = super().to_representation(instance)
        
        # Generate tokens
        tokens = self.get_tokens(instance)
        
        # Add tokens to the user data
        user_data['tokens'] = tokens
        
        # Return all user data in response
        # Include additional fields that are not part of the input
        user_data['id'] = instance.id
        user_data['full_name'] = instance.full_name
        user_data['city'] = instance.city
        user_data['state'] = instance.state
        user_data['postal_code'] = instance.postal_code
        user_data['address'] = instance.address
        user_data['bio'] = instance.bio
        user_data['badge'] = instance.badge
        user_data['user_type'] = instance.user_type
        user_data['profile_pic_url'] = instance.profile_pic_url
        user_data['location'] = instance.location
        user_data['default_location'] = instance.default_location
        user_data['total_number_of_rating'] = instance.total_number_of_rating
        user_data['average_rating'] = instance.average_rating
        user_data['total_rating'] = instance.total_rating
        user_data['driver_total_number_of_rating'] = instance.driver_total_number_of_rating
        user_data['driver_average_rating'] = instance.driver_average_rating
        user_data['driver_total_rating'] = instance.driver_total_rating
        user_data['document_uploaded'] = instance.document_uploaded
        user_data['setting_applied'] = instance.setting_applied
        user_data['discovery_radius'] = instance.discovery_radius
        user_data['no_delivery'] = instance.no_delivery
        user_data['recent_orders'] = instance.recent_orders
        user_data['nearest_orders'] = instance.nearest_orders
        user_data['highest_earning_orders'] = instance.highest_earning_orders
        user_data['least_earning_orders'] = instance.least_earning_orders
        user_data['filter_type'] = instance.filter_type
        user_data['email_id'] = instance.email_id
        user_data['created_at'] = instance.created_at
        user_data['updated_at'] = instance.updated_at
        
        return user_data

    def get_tokens(self, user):
        # Generate refresh and access tokens
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }


class FileUploadSerializern(serializers.Serializer):
    file = serializers.FileField()  # This will handle the file upload







class profileUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class profileUserSerializernew(serializers.ModelSerializer):
    image = serializers.ImageField(required=False)  # Remove this line if it exists

    class Meta:
        model = User
        fields = '__all__'























































