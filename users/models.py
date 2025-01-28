from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, AbstractUser
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
import uuid
from django.utils.crypto import get_random_string

# Remove duplicate import
# from django.contrib.auth.base_user import BaseUserManager

class MyUserManager(BaseUserManager):
    """Custom user manager for handling user creation and superuser creation."""
    
    def create_user(self, email, contact, username, password=None, **extra_fields):
        """
        Creates and saves a regular user.
        
        Args:
            email: User's email address (required)
            contact: User's contact information (required)
            username: User's username (required)
            password: User's password (optional)
            **extra_fields: Additional fields for user creation
        """
        if not contact:
            raise ValueError('The Contact field must be set')
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, contact=contact, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, contact, username, password=None, **extra_fields):
        """
        Creates and saves a superuser with administrative privileges.
        
        Sets is_admin and is_superuser to True by default.
        """
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_admin') is not True:
            raise ValueError('Superuser must have is_admin=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, contact, username, password, **extra_fields)

class CustomUserIDField(models.CharField):
    """Custom field for generating unique 6-digit user IDs that don't start with 0."""
    
    def pre_save(self, model_instance, add):
        """
        Generates a 6-digit ID for new instances.
        Ensures the generated ID is between 100000 and 999999.
        """
        if add:
            while True:
                new_id = get_random_string(length=6, allowed_chars='123456789')
                if new_id[0] != '0':
                    return new_id
        return super().pre_save(model_instance, add)

class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    Uses email as the primary identifier for authentication.
    """
    
    # Basic Information
    full_name = models.CharField(max_length=150, null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    id = CustomUserIDField(primary_key=True, max_length=6, editable=False)
    
    # User Type Definition
    USER_TYPE_CHOICES = (
        ('client', 'client'),
        ('admin', 'admin'),
        ('super_admin', 'Super Admin'),
    )
    
    # Contact and Location Information
    contact = models.CharField(max_length=255, blank=True)
    device_token = models.CharField(max_length=255, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    Trade_radius = models.CharField(max_length=6, null=True, blank=True)
    
    # Authentication and Verification
    is_registered = models.BooleanField(default=False)
    verify = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    username = models.CharField(max_length=200)
    user_type = models.CharField(max_length=255, default='client', choices=USER_TYPE_CHOICES)
    email = models.EmailField(verbose_name='Email', max_length=255, unique=True)
    
    # OAuth Related Fields
    origin = models.CharField(max_length=200, null=True, blank=True)
    uid = models.CharField(max_length=200, null=True, blank=True)
    
    # Permission and Status Fields
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Profile and Social Media
    image = models.ImageField(upload_to='user_images/', null=True, blank=True)
    visible_to_user = models.BooleanField(default=True)
    twitter_url = models.URLField(max_length=255, null=True, blank=True)
    instagram_url = models.URLField(max_length=255, null=True, blank=True)
    facebook_url = models.URLField(max_length=255, null=True, blank=True)

    objects = MyUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['contact', 'username']

    def __str__(self):
        """Returns the user's email as string representation."""
        return self.email

    def has_perm(self, perm, obj=None):
        """Checks if user has a specific permission."""
        return self.is_admin

    def has_module_perms(self, app_label):
        """Checks if user has permissions to view the app `app_label`."""
        return True

    @property
    def is_staff(self):
        """Returns whether the user has staff status based on admin status."""
        return self.is_admin

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "User"