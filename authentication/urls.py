from django.urls import path
from . import views
from .views import *
from django.contrib.auth import views as auth_view
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    #apis urls
    path('', HomePage.as_view(), name='home'),
    path('signup/', UserSignupView.as_view(), name='user-signup'),
    path('api_login/', LoginView.as_view(), name='token_obtain_pair'),
    path("assign/", AssignDoctorView.as_view(), name="assign-doctor"),
    path("my-doctors/", PatientDoctorsView.as_view(), name="patient-doctors"),
    path("my-patients/", DoctorPatientsView.as_view(), name="doctor-patients"),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api_logout/', LogoutView.as_view(), name='api_logout'),
    path('doctor-notes/submit/', SubmitDoctorNoteView.as_view(), name='submit_doctor_note'),
    path('doctor-notes/retrieve/<int:patient_id>/', RetrieveDoctorNoteView.as_view(), name='retrieve_doctor_note'),
    path("checklist/complete/", MarkChecklistCompletedView.as_view(), name="mark-checklist-completed"),
    path("plan/complete/", MarkPlanTaskCompletedView.as_view(), name="mark-plan-completed"),
    path("reminders/upcoming/", UpcomingRemindersView.as_view(), name="upcoming-reminders"),
    #django class based view urls for testing my work
    
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

