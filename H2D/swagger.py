# Import required modules from Django REST framework and drf-yasg
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Create a schema view for API documentation using drf-yasg
schema_view = get_schema_view(
    # Configure OpenAPI information
    openapi.Info(
        title="Here2Dare",                # API name/title
        default_version='v1',             # API version
        description="Test description",    # API description
        terms_of_service="https://www.google.com/policies/terms/",  # Terms of service URL
        contact=openapi.Contact(email="muhammadobaidullah1122@gmail.com"),  # Contact information
        license=openapi.License(name="BSD License"),    # License information
    ),
    public=True,                          # Make the documentation publicly accessible
    permission_classes=(permissions.AllowAny,),  # Allow any user to access the documentation
)