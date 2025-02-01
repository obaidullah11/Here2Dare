# Core Django imports and configurations
from pathlib import Path
import os
from datetime import timedelta

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Security settings
SECRET_KEY = 'django-insecure-za72^!nk_jf^uj=#w4!(o*h7!nf*)t1s&54sbtou)z_=5e+*$t'

# Password hashing configurations
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]

# Email configuration settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'muhammadobaidullah1122@gmail.com'
EMAIL_HOST_PASSWORD = 'owgv yxkq kfin ylru'


# Development and deployment settings
DEBUG = True
ALLOWED_HOSTS = ['*']

# Application definition - includes Django core apps and third-party integrations
INSTALLED_APPS = [
    # 'admin_adminlte.apps.AdminAdminlteConfig',
    'jazzmin',  # Admin panel theme
    # Django default apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third-party apps
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'users',
    'sslserver',
    'drf_yasg',
    'file_storage',
    # 'admin_tools.stats',
    # 'admin_tools',
    # 'admin_tools_stats',  # Swagger/OpenAPI documentation
]

SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    },
    'USE_SESSION_AUTH': False,
}
JAZZMIN_UI_TWEAKS = {
     "sidebar_fixed": True,
}
# Middleware configuration - handles request/response cycle
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # Add your frontend URL here
    "http://127.0.0.1:8000",
]
CORS_ALLOW_CREDENTIALS = True
ROOT_URLCONF = 'H2D.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'H2D.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'h2ddb',
    }
}

# Custom user model configuration
AUTH_USER_MODEL = 'users.User'

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]
JAZZMIN_SETTINGS = {
    "site_title": "Here2Dare Admin",
    "site_header": "Here2Dare Admin Panel",
    "site_brand": "Here2Dare",
    "welcome_sign": "Welcome to Here2Dare Admin",
    "copyright": "Here2Dare 2025",
    "topmenu_links": [
        {"name": "Home", "url": "admin:index"},
        {"app": "user"},
    ],
    "navigation_expanded": True,
    "icons": {
        "auth": "fas fa-users-cog",
        "auth.user": "fas fa-user",
        "auth.Group": "fas fa-users",
    },
    "default_icon_parents": "fas fa-chevron-circle-right",
    "default_icon_children": "fas fa-circle",
    "related_modal_active": True,
    "order_with_respect_to": ["auth", "user"],
    "custom_css": None,
    "hide_models": ['auth.group'],
    "dashboard": {
        "widgets": [
            {
                "type": "count",
                "model": "auth.User",
                "title": "Total Users",
                "icon": "fas fa-users",
                "url": "admin:auth_user_changelist",
                "classes": "bg-primary text-white",
            },
            {
                "type": "count",
                "model": "auth.Group",
                "title": "Total Groups",
                "icon": "fas fa-users-cog",
                "url": "admin:auth_group_changelist",
                "classes": "bg-info text-white",
            },
            {
                "type": "custom",
                "title": "Quick Stats",
                "content": """
                    <ul>
                        <li>Recent Orders: 75</li>
                        <li>Pending Tasks: 5</li>
                        <li>Active Users: 120</li>
                    </ul>
                """,
                "icon": "fas fa-chart-line",
                "classes": "bg-warning text-white",
            },
        ]
    }
}
# File upload and localization settings
MAX_UPLOAD_SIZE = "429916160"  # Approximately 410MB
LANGUAGE_CODE = 'en-us'
TIME_ZONE = "Asia/Karachi"
USE_I18N = True
USE_TZ = True

# Media files configuration (user-uploaded files)
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework settings for API
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.coreapi.AutoSchema',
}

# Static files configuration (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, '../', 'static')

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=20),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),

    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "USER_AUTHENTICATION_RULE": "rest_framework_simplejwt.authentication.default_user_authentication_rule",

    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",

    "JTI_CLAIM": "jti",

    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainPairSerializer",
    "TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSerializer",
    "TOKEN_VERIFY_SERIALIZER": "rest_framework_simplejwt.serializers.TokenVerifySerializer",
    "TOKEN_BLACKLIST_SERIALIZER": "rest_framework_simplejwt.serializers.TokenBlacklistSerializer",
}

# CORS settings for API access
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_HEADERS = ['*']

# Security and UI settings
X_FRAME_OPTIONS = 'SAMEORIGIN'
USE_DJANGO_JQUERY = True

# Logging directory setup
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'knet': {  # Add your app name here
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
