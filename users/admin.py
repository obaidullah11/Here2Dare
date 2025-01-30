from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User  # import your custom User model

class CustomUserAdmin(UserAdmin):
    # Fields to be displayed in the admin form
    model = User
    list_display = (
        'email', 'username', 'full_name', 'is_active', 'is_admin', 'is_registered'
    )
    list_filter = ('is_active', 'is_admin')
    search_fields = ('email', 'username', 'full_name')
    ordering = ('email',)

    # Fields displayed when editing the user
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('full_name', 'phone_number', 'address', 'city', 'state', 'postal_code', 'country_code')}),
        ('Permissions', {'fields': ('is_active', 'is_admin',  'is_banned', 'is_deleted')}),
        ('Important Dates', {'fields': ('last_login',  )}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'full_name', 'phone_number', 'user_type', 'is_active',  'is_admin')}
        ),
    )
    filter_horizontal = ()

# Register the custom User model with the custom admin
admin.site.register(User, CustomUserAdmin)
