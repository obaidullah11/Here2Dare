# Generated by Django 5.0 on 2024-11-04 13:37

import django.utils.timezone
import users.models
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('full_name', models.CharField(blank=True, max_length=150, null=True)),
                ('address', models.TextField(blank=True, null=True)),
                ('id', users.models.CustomUserIDField(editable=False, max_length=6, primary_key=True, serialize=False)),
                ('contact', models.CharField(blank=True, max_length=255)),
                ('device_token', models.CharField(blank=True, max_length=255)),
                ('latitude', models.DecimalField(blank=True, decimal_places=6, max_digits=9, null=True)),
                ('longitude', models.DecimalField(blank=True, decimal_places=6, max_digits=9, null=True)),
                ('Trade_radius', models.CharField(blank=True, max_length=6, null=True)),
                ('is_registered', models.BooleanField(default=False)),
                ('verify', models.BooleanField(default=False)),
                ('otp_code', models.CharField(blank=True, max_length=6, null=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('username', models.CharField(max_length=200)),
                ('user_type', models.CharField(choices=[('client', 'client'), ('admin', 'admin'), ('super_admin', 'Super Admin')], default='client', max_length=255)),
                ('email', models.EmailField(max_length=255, unique=True, verbose_name='Email')),
                ('origin', models.CharField(blank=True, max_length=200, null=True)),
                ('uid', models.CharField(blank=True, max_length=200, null=True)),
                ('is_superuser', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('image', models.ImageField(blank=True, null=True, upload_to='user_images/')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'User',
                'verbose_name_plural': 'User',
            },
        ),
    ]
