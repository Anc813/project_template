# Generated by Django 2.1.7 on 2019-09-13 08:03

import accounts.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='Email')),
                ('username', models.CharField(blank=True, max_length=300, null=True, verbose_name='Username')),
                ('is_active', models.BooleanField(default=False, verbose_name='Active')),
                ('is_admin', models.BooleanField(default=False, verbose_name='Admin')),
                ('registered', models.DateTimeField(auto_now_add=True, verbose_name='Registered')),
            ],
            options={
                'verbose_name': 'User',
                'verbose_name_plural': 'Users',
            },
        ),
    ]
