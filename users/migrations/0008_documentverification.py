# Generated by Django 5.0 on 2025-01-30 19:16

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_alter_user_options_remove_user_image_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='DocumentVerification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document_file', models.FileField(upload_to='documents/')),
                ('verification_status', models.CharField(choices=[('Pending', 'Pending'), ('Verified', 'Verified'), ('Rejected', 'Rejected')], default='Pending', max_length=20, null=True)),
                ('verification_date', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='document_verifications', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Document Verification',
                'verbose_name_plural': 'Document Verifications',
            },
        ),
    ]
