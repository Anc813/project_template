"""
Django settings for profit_reporter project.

Generated by 'django-admin startproject' using Django 1.8.

For more information on this file, see
https://docs.djangoproject.com/en/1.8/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.8/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os

WEBSITE_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
PROJECT_ROOT = os.path.abspath(os.path.dirname(WEBSITE_ROOT))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.8/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = ''

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # 'pipeline',
    # 'rest_framework',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(WEBSITE_ROOT, 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.8/ref/settings/#databases

### SQLITE ###
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'project.db',
        # 'USER': '',
        # 'PASSWORD': '',
        # 'HOST': '',
        # 'PORT': 5432
    }
}
### SQLITE ###

# ## POSTGRESQL ###
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql_psycopg2',
#         'NAME': 'project_db',
#         'USER': 'project_usr',
#         'PASSWORD': 'project_db_password',
#         'HOST': 'localhost',
#         'PORT': 5432
#     }
# }
# # CREATE USER project_usr with password 'project_db_password';
# # CREATE DATABASE project_db OWNER project_usr;
#
# ## POSTGRESQL ###


# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = False


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.8/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(PROJECT_ROOT, 'static_root')

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(PROJECT_ROOT, 'media_root')


STATICFILES_DIRS = (
    # ('js', os.path.join(PROJECT_ROOT, 'coffee')),
    # ('js', os.path.join(PROJECT_ROOT, 'js')),
    # ('css', os.path.join(PROJECT_ROOT, 'less')),
    # ('css', os.path.join(PROJECT_ROOT, 'css')),
    # ('fonts', os.path.join(PROJECT_ROOT, 'fonts')),
    # ('images', os.path.join(PROJECT_ROOT, 'images')),
    # ('img', os.path.join(PROJECT_ROOT, 'img')),
    # ('vendor', os.path.join(PROJECT_ROOT, 'bower_components')),
)

STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
    # 'pipeline.finders.PipelineFinder',
)

# STATICFILES_STORAGE = 'pipeline.storage.PipelineCachedStorage'

# PIPELINE_CSS_COMPRESSOR = None
# PIPELINE_JS_COMPRESSOR = None

# PIPELINE_COMPILERS = (
#     'pipeline.compilers.less.LessCompiler',
#     'pipeline.compilers.coffee.CoffeeScriptCompiler',
# )

# PIPELINE_CSS = {
#     'styles': {
#         'source_filenames': (
#         ),
#         'output_filename': '',
#     },
# }

# PIPELINE_JS = {
#     'scripts': {
#         'source_filenames': (
#         ),
#         'output_filename': '',
#     }
# }


# REST_FRAMEWORK = {
#     'DEFAULT_PERMISSION_CLASSES': (
#         'rest_framework.permissions.IsAuthenticated',
#     ),
#     'DEFAULT_AUTHENTICATION_CLASSES': (
#         'rest_framework.authentication.SessionAuthentication',
#         'rest_framework.authentication.BasicAuthentication',
#     ),
#     'DEFAULT_RENDERER_CLASSES': (
#         'rest_framework.renderers.JSONRenderer',
#         # 'rest_framework.renderers.JSONPRenderer',
#         'rest_framework.renderers.MultiPartRenderer',
#     ),
# }
