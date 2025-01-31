from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
import uuid
from rest_framework_simplejwt.tokens import RefreshToken  # Importing RefreshToken

# Custom field for generating a unique user ID
class CustomUserIDField(models.CharField):
    def pre_save(self, model_instance, add):
        # Generate a 24-character hexadecimal ID if it's a new instance
        if add:
            return uuid.uuid4().hex[:6]  # Slicing to get the first 6 characters for a custom ID length
        else:
            return super().pre_save(model_instance, add)

class MyUserManager(BaseUserManager):
    def create_user(self, email, phone_number, username=None, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        if not phone_number:
            raise ValueError('The Phone Number field must be set')

        email = self.normalize_email(email)
        if not username:
            username = email  # Set username to email if not provided
        user = self.model(email=email, phone_number=phone_number, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, phone_number, username=None, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_admin') is not True:
            raise ValueError('Superuser must have is_admin=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        if not username:
            username = email
        return self.create_user(email, phone_number, username, password, **extra_fields)

class User(AbstractUser):
    id = CustomUserIDField(primary_key=True, max_length=6, editable=False)  # Using CustomUserIDField
    full_name = models.CharField(max_length=150, blank=True, null=True)
    first_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    phone_number = models.CharField(max_length=15, unique=True, blank=True, null=True)
    full_number = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(unique=True, blank=True, null=True)
    is_admin = models.BooleanField(default=False, null=True)
    is_email_verified = models.BooleanField(default=False, null=True)
    # is_verified = models.BooleanField(default=False, null=True)
    is_approved = models.BooleanField(default=False, null=True)
    is_deleted = models.BooleanField(default=False, null=True)
    is_mute = models.BooleanField(default=False, null=True)
    is_stripe_connect = models.BooleanField(default=False, null=True)
    device_type = models.CharField(max_length=50, blank=True, null=True)
    device_token = models.CharField(max_length=255, blank=True, null=True)
    country_code = models.CharField(max_length=5, blank=True, null=True)
    country_iso = models.CharField(max_length=5, blank=True, null=True)
    country = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=50, blank=True, null=True)
    state = models.CharField(max_length=50, blank=True, null=True)
    postal_code = models.CharField(max_length=10, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    badge = models.CharField(max_length=50, blank=True, null=True)
    user_type = models.CharField(max_length=20, choices=[('Shopper', 'Shopper'), ('Driver', 'Driver'), ('Admin', 'Admin')], default='Shopper', null=True)
    profile_pic_url = models.URLField(max_length=500, blank=True, null=True)
    location = models.JSONField(blank=True, null=True)
    default_location = models.JSONField(blank=True, null=True)
    total_number_of_rating = models.IntegerField(default=0, null=True)
    average_rating = models.FloatField(default=0.0, null=True)
    total_rating = models.IntegerField(default=0, null=True)
    driver_total_number_of_rating = models.IntegerField(default=0, null=True)
    driver_average_rating = models.FloatField(default=0.0, null=True)
    driver_total_rating = models.IntegerField(default=0, null=True)
    document_uploaded = models.BooleanField(default=False, null=True)
    access_token = models.TextField(blank=True, null=True)
    setting_applied = models.BooleanField(default=False, null=True)
    discovery_radius = models.IntegerField(default=0, null=True)
    no_delivery = models.BooleanField(default=False, null=True)
    recent_orders = models.BooleanField(default=False, null=True)
    nearest_orders = models.BooleanField(default=False, null=True)
    highest_earning_orders = models.BooleanField(default=False, null=True)
    least_earning_orders = models.BooleanField(default=False, null=True)
    filter_type = models.CharField(max_length=50, default='None', null=True)
    email_id = models.EmailField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    
    objects = MyUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone_number']
    
    def __str__(self):
        return self.email
    
    def has_perm(self, perm, obj=None):
        return self.is_admin
    
    def has_module_perms(self, app_label):
        return True
    
    @property
    def is_staff(self):
        return self.is_admin
    
    def get_jwt_token(self):
        """
        Generates a JWT token for the user.
        """
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"



class DocumentVerification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="document_verifications")
    document_file = models.FileField(upload_to='documents/', blank=False, null=False)
    
    verification_status = models.CharField(max_length=20, choices=[('Pending', 'Pending'), ('Verified', 'Verified'), ('Rejected', 'Rejected')], default='Pending', null=True)
    verification_date = models.DateTimeField(null=True, blank=True)
    
    
    def __str__(self):
        return f"{self.user.full_name} - Document Verification"

    class Meta:
        verbose_name = "Document Verification"
        verbose_name_plural = "Document Verifications"