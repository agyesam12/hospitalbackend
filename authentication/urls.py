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
    #admin urls
    path('register/user/', AdminRegisterUsersView.as_view(), name='admin_create_user'),
    path('users/', AdminUserListView.as_view(), name='admin_user_list'),
    path('patients/',AdminPatientListView.as_view(), name= "patient_lists"),
    path('doctors/',AdminDoctorListView.as_view(), name= "doctor_lists"),
    path('user/<str:id>/', AdminUserDetailView.as_view(), name='admin_user_detail'),
    path('user/<str:id>/change-password/', AdminChangeUserPasswordView.as_view(), name='admin_change_user_password'),
]

