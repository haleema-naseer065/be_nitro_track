import os
from pathlib import Path
from mongoengine import connect

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-key'
SECRET_KEY_JWT = os.getenv("JWT_SECRET", "your-secret-key")  # Change this to a secure key


DEBUG = True

ALLOWED_HOSTS = [
    "benitrotrack-production.up.railway.app",
    "localhost",
    "127.0.0.1",
]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'app.middleware.JWTAuthenticationMiddleware',  
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'Nitro_Track.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

WSGI_APPLICATION = 'Nitro_Track.wsgi.application'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',  # Change this for PostgreSQL or MySQL
        'NAME': BASE_DIR / "db.sqlite3",
    }
}

MONGO_DB_NAME = "nitro-app"
MONGO_DB_HOST = "mongodb+srv://haleemanaseer065:Haleema065@cluster0.xz9bo.mongodb.net/nitro-app?retryWrites=true&w=majority&appName=Cluster0"

connect(
    db=MONGO_DB_NAME,
    host=MONGO_DB_HOST
)
# connect('nitro-app', host='mongodb+srv://haleemanaseer065:ONVO73fO1THqmQBt@cluster0.xz9bo.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0') 
AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'




