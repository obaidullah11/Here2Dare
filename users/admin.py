from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User
from django.contrib import admin
from .models import DocumentVerification
from django.utils.html import format_html

# Customizing the UserAdmin to work with the custom User model
class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['id','email', 'full_name', 'phone_number', 'is_admin',  'is_email_verified', 'is_approved', 'created_at']
    list_filter = ['is_admin',  'is_email_verified', 'is_approved', 'is_deleted']
    search_fields = ['email', 'username', 'phone_number']
    ordering = ['created_at']
    readonly_fields = ('id', 'created_at', 'updated_at')
    
    fieldsets = (
        (None, {
            'fields': ('email', 'password')
        }),
        ('Personal info', {
            'fields': ('full_name', 'phone_number', 'username', 'bio', 'profile_pic_url', 'location', 'address')
        }),
        ('Permissions', {
            'fields': ('is_admin',  'is_email_verified', 'is_approved', 'is_deleted', 'is_mute')
        }),
        ('Advanced settings', {
            'fields': ('user_type', 'device_type', 'device_token', 'country_code', 'country_iso', 'city', 'state', 'postal_code', 'badge')
        }),
        ('Other Information', {
            'fields': ('document_uploaded', 'access_token', 'setting_applied', 'discovery_radius', 'filter_type', 'email_id')
        }),
        ('Ratings', {
            'fields': ('total_number_of_rating', 'average_rating', 'total_rating', 'driver_total_number_of_rating', 'driver_average_rating', 'driver_total_rating')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        })
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'phone_number', 'password1', 'password2', 'is_admin',  'is_email_verified')
        }),
    )
    
    # Making sure password is required
    def save_model(self, request, obj, form, change):
        if not obj.password:
            raise ValueError('Password is required!')
        super().save_model(request, obj, form, change)

# Registering the custom User model with the custom UserAdmin
admin.site.register(User, CustomUserAdmin)



class DocumentVerificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'document_file_preview', 'verification_status', 'verification_date')  # Display relevant fields
    list_filter = ('verification_status',)  # Optional: Filter by verification status
    search_fields = ('user__full_name', 'document_file')  # Optional: Search by user name or document file
    
    def document_file_preview(self, obj):
        if obj.document_file:
            return format_html('<a href="{}" target="_blank">Preview</a>', obj.document_file.url)
        return 'No file uploaded'
    document_file_preview.short_description = 'Document Preview'  # Label in the admin list view

admin.site.register(DocumentVerification, DocumentVerificationAdmin)