from django.urls import path
from . import views
from .views import ViewUsers, DeleteUser


urlpatterns = [
    path('api/sign-up', views.sign_up, name='create_user'),
    path('api/sign-in', views.signin_user, name='get_users'),  
    path('api/me', views.user_profile, name='user_profile'), 

    # New Endpoints
    path('users/view/', ViewUsers.as_view(), name='view_users'),
    path('users/delete/', DeleteUser.as_view(), name='delete_user'),
    path('profile/edit/', views.edit_profile, name='edit_profile'),
]
