from django.urls import path
from . import views
from .views import *
from django.contrib.auth import views as auth_view


urlpatterns = [
    path('', HomePage.as_view(), name='home'),
    path('signup/', views.SignupView.as_view(), name='signup'),
    path('register/',UserSignUp.as_view(), name='register'),
    path('login/',LoginPageView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/update/', ProfileUpdateView.as_view(), name='profile_update'),
    path('update_password/',auth_view.PasswordChangeView.as_view(template_name="update_password.html",success_url="user_dashboard" ),name='update_password'),
]

