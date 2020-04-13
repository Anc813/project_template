import hashlib
from datetime import timedelta, datetime
from string import digits

from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string

from core.helper import send_email

__all__ = ['User', 'AuthCode']


# region User
class UserManager(BaseUserManager):
    def create_user(self, email, username=None, password=None):
        if not email:
            raise ValueError('User must have Email')

        user = self.model(
            username=username,
            email=email,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, username=None):
        user = self.create_user(
            username=username,
            email=email,
            password=password,
        )
        user.is_admin = True
        user.is_active = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    FORBIDDEN_PERMISSIONS = {'add', 'change', 'delete'}

    email = models.EmailField(unique=True, verbose_name='Email')
    # username = models.CharField(max_length=300, null=True, blank=True, verbose_name='Username')

    is_active = models.BooleanField(default=False, verbose_name='Active')
    is_admin = models.BooleanField(default=False, verbose_name='Admin')

    is_readonly = models.BooleanField(default=False)

    registered = models.DateTimeField(auto_now_add=True, verbose_name='Registered')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def send_email(self, subj, msg, html_msg=None, desc='manual'):
        args, kwargs = (subj, msg, [self.email]), {'html_message': html_msg, 'description': desc}
        send_email(*args, **kwargs)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # region std
    def get_full_name(self):
        return self.email

    def get_short_name(self):
        return self.email

    def has_perm(self, perm, obj=None):
        if not self.is_readonly:
            return True

        try:
            app, rest = perm.split('.')
            permission, model_name = rest.split('_', 1)
            return permission not in self.FORBIDDEN_PERMISSIONS
        except IndexError:
            return True

    def has_module_perms(self, app_label):
        return True
    # endregion

    def __str__(self):
        return self.email

    @property
    def is_staff(self):
        return self.is_admin

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
# endregion

