from django.contrib import admin
from .models import UploadedFile

class UploadedFileAdmin(admin.ModelAdmin):
    list_display = ('file', 'uploaded_at')  # Display these fields in the admin list view
    search_fields = ('file',)  # Enable search by file field

admin.site.register(UploadedFile, UploadedFileAdmin)
