from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import *

# from . views import *

urlpatterns = [

path('create_file_url/', FileUploadView.as_view(), name='upload_file'),
path('getfileurl/', FileListView.as_view(), name='list_files'),
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)