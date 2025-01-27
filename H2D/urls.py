from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from .swagger import schema_view

 # Import your routing configuration for WebSocket connections

urlpatterns = [
    path('', schema_view.with_ui('swagger',
                                         cache_timeout=0), name='schema-swagger-ui'),
    path('admin/', admin.site.urls),
    path('api/user/', include('users.urls')),
  
    # Add path for WebSocket connections

]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
