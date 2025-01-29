from django.urls import path
from . import views

urlpatterns = [
    path('api/sign-up', views.sign_up, name='create_user'),
    path('api/sign-in', views.signin_user, name='get_users'),  
    path('api/me', views.user_profile, name='user_profile'), 
]
