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












































































class UserSerializer(serializers.ModelSerializer):
    social_urls = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'user_type', 'image', 'device_token', 'address',
            'visible_to_user', 'is_active', 'is_superuser', 'full_name',
            'longitude', 'latitude', 'Trade_radius', 'social_urls'
        ]

    def get_social_urls(self, obj):
        return {
            'twitter_url': obj.twitter_url,
            'instagram_url': obj.instagram_url,
            'facebook_url': obj.facebook_url
        }
class AdminLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = authenticate(email=email, password=password)
        if user is None:
            raise serializers.ValidationError("Invalid login credentials.")

        # Check if the user is an admin
        if user.user_type != 'admin':
            raise serializers.ValidationError("Access denied. User is not an admin.")

        # Check if the user is active
        if not user.is_active:
            raise serializers.ValidationError("This account is inactive.")

        data['user'] = user
        return data

# class SocialRegistrationSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(required=True)
#     full_name = serializers.CharField(required=False, allow_blank=True)
#     origin = serializers.CharField(required=False, allow_blank=True)
#     uid = serializers.CharField(required=False, allow_blank=True)

#     class Meta:
#         model = User
#         fields = ['email', 'full_name', 'origin', 'uid']

#     def create(self, validated_data):
#         """
#         Create a new user or update the existing user based on email.
#         """
#         email = validated_data.get('email')
#         full_name = validated_data.get('full_name', '')
#         origin = validated_data.get('origin', '')
#         uid = validated_data.get('uid', '')

#         # Check if the user already exists
#         user, created = User.objects.get_or_create(email=email, defaults={
#             'full_name': full_name,
#             'origin': origin,
#             'uid': uid,
#         })

#         # If user already exists, update the fields
#         if not created:
#             user.full_name = full_name
#             user.origin = origin
#             user.uid = uid
#             user.save()

#         return user
class SocialRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    username = serializers.CharField(required=True)  # New field
    full_name = serializers.CharField(required=False, allow_blank=True)
    origin = serializers.CharField(required=False, allow_blank=True)
    uid = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'full_name', 'origin', 'uid']  # Include username

    def create(self, validated_data):
        """
        Create a new user or update the existing user based on email.
        """
        email = validated_data.get('email')
        username = validated_data.get('username')  # Handle username
        full_name = validated_data.get('full_name', '')
        origin = validated_data.get('origin', '')
        uid = validated_data.get('uid', '')

        # Check if the user already exists
        user, created = User.objects.get_or_create(email=email, defaults={
            'username': username,
            'full_name': full_name,
            'origin': origin,
            'uid': uid,
        })

        # If user already exists, update the fields
        if not created:
            user.username = username  # Update username
            user.full_name = full_name
            user.origin = origin
            user.uid = uid
            user.save()

        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username','email','user_type', 'image','device_token','longitude','latitude','Trade_radius','address','contact','visible_to_user','twitter_url','facebook_url','instagram_url']
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'user_type', 'image', 'device_token', 'full_name', 'address','longitude','latitude','contact' ]
        extra_kwargs = {
            'user_type': {'default': 'client'},  # Set default value for user_type if not provided
            'image': {'required': False},  # Allow image to be optional
            'device_token': {'required': False},
            'full_name': {'required': False},  # Allow first_name to be optional
              # Allow last_name to be optional
            'address': {'required': False},
            'longitude': {'required': False},  # Allow last_name to be optional
            'latitude': {'required': False},
             'contact' : {'required': False},








            # Allow device_token to be optional
        }

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(password=password, **validated_data)
        return user
class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']

# class UserProfileSerializer(serializers.ModelSerializer):
#   class Meta:
#     model = User
#     fields = ['id', 'email', 'name','image']
# class UserProfileSerializer(serializers.ModelSerializer):
#     social_urls = serializers.SerializerMethodField()
#     class Meta:
#         model = User
#         fields = ('id', 'email', 'username', 'user_type', 'is_active', 'is_admin', 'created_at', 'updated_at', 'image','is_registered','is_deleted','full_name', 'address','visible_to_user','longitude','latitude','social_urls')
#     def get_social_urls(self, obj):
#         return {
#             'twitter_url': obj.twitter_url,
#             'instagram_url': obj.instagram_url,
#             'facebook_url': obj.facebook_url
#         }

class UserChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    new_password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        user = self.context.get('user')
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')

        if not user.check_password(old_password):
            raise serializers.ValidationError("Incorrect old password")

        if old_password == new_password:
            raise serializers.ValidationError("New password must be different from old password")

        return attrs

    def save(self):
        user = self.context.get('user')
        new_password = self.validated_data.get('new_password')
        user.set_password(new_password)
        user.save()

class UserChangeP4asswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    password = attrs.get('password')
    password2 = attrs.get('password2')
    user = self.context.get('user')
    if password != password2:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    user.set_password(password)
    user.save()
    return attrs

class SendPasswordResetEmailSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    fields = ['email']

  def validate(self, attrs):
    email = attrs.get('email')
    if User.objects.filter(email=email).exists():
      user = User.objects.get(email = email)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
      print('Password Reset Link', link)
      # Send EMail
      body = 'Click Following Link to Reset Your Password '+link
      data = {
        'subject':'Reset Your Password',
        'body':body,
        'to_email':user.email
      }
      # Util.send_email(data)
      return attrs
    else:
      raise serializers.ValidationError('You are not a Registered User')
from rest_framework import serializers

class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, max_length=128)
    confirm_password = serializers.CharField(min_length=8, max_length=128)

    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError("Passwords do not match")

        return data

class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != password2:
        raise serializers.ValidationError("Password and Confirm Password doesn't match")
      id = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token is not Valid or Expired')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user, token)
      raise serializers.ValidationError('Token is not Valid or Expired')
class DriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'contact', 'image']