from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, AbstractUser
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
import uuid
from django.utils.crypto import get_random_string

from django.contrib.auth.base_user import BaseUserManager

class MyUserManager(BaseUserManager):
    def create_user(self, email, phone_number, username=None, password=None, **extra_fields):
        """
        Creates and saves a User with the given email, phone_number, username, and password.
        """
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
        """
        Creates and saves a superuser with the given email, phone_number, username, and password.
        """
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_admin') is not True:
            raise ValueError('Superuser must have is_admin=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        if not username:
            username = email  # Automatically use email as the username if not provided

        return self.create_user(email, phone_number, username, password, **extra_fields)


class CustomUserIDField(models.CharField):
    def pre_save(self, model_instance, add):
        # Generate a 6-digit ID if it's a new instance
        if add:
            return get_random_string(length=6, allowed_chars='0123456789')
        else:
            return super().pre_save(model_instance, add)
# Create your models here.
class User(AbstractUser):
    full_name = models.CharField(max_length=150, null=True, blank=True)
    country = models.CharField(max_length=50, blank=True)
    phone_number = models.CharField(max_length=15, blank=True)

    # Address Information
    city = models.CharField(max_length=50, blank=True)
    state = models.CharField(max_length=50, blank=True)
    postal_code = models.CharField(max_length=10, blank=True)
    country_code = models.CharField(max_length=5, blank=True)
    address = models.TextField(null=True, blank=True)
    
    id = CustomUserIDField(primary_key=True, max_length=6, editable=False)
    
    device_token = models.CharField(max_length=255, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    
    is_registered = models.BooleanField(default=False)
    verify = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, null=True, blank=True)
    is_deleted = models.BooleanField(default=False)
    
    user_type = models.CharField(
        max_length=20,
        choices=[('Shopper', 'Shopper'), ('driver', 'Driver'), ('admin', 'Admin')],
        default='Shopper',
    )

    email = models.EmailField(verbose_name='Email', max_length=255, unique=True)
    origin = models.CharField(max_length=200, null=True, blank=True)
    uid = models.CharField(max_length=200, null=True, blank=True)

    is_banned = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    image = models.ImageField(upload_to='user_images/', null=True, blank=True)
    language = models.CharField(max_length=10, default='en')
    bio = models.TextField(blank=True)

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

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "User"
