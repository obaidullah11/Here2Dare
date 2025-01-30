from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from .swagger import schema_view
from rest_framework_simplejwt .views import(TokenObtainPairView,TokenRefreshView)

# Define URL patterns for the project
urlpatterns = [
    # Swagger UI endpoint - API documentation interface
    path('', schema_view.with_ui('swagger',
                                         cache_timeout=0), name='schema-swagger-ui'),
    
    # Django admin interface
    path('admin/', admin.site.urls),
    # path('adminlte/', include('admin_adminlte.urls')),
    # path("unfold-admin/", new_admin_site.urls),
    
    # User API endpoints (currently commented out)
    path('', include('users.urls')),
    
    # JWT Authentication endpoints
    # Endpoint to obtain JWT token pair (access and refresh tokens)
    path('api/token',TokenObtainPairView.as_view(),name='token_obtain_pair'),
    
    # Endpoint to refresh JWT access token using refresh token
    path('api/token/referesh/',TokenRefreshView.as_view(),name='token_refresh'),
]

# Serve static files during development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
