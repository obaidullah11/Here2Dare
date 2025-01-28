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
    
    # User API endpoints (currently commented out)
    path('api/user/', include('users.urls')),
    
    
]

# Serve static files during development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
