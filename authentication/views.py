from django.shortcuts import render,redirect

# Create your views here.
from django.contrib import messages
from rest_framework.response import Response
from rest_framework.views import APIView
from django.views.generic import CreateView,UpdateView,DetailView,DeleteView,View,FormView,ListView
from .models import User
from packages.logentry import create_log_entry
from django.contrib.contenttypes.models import ContentType
from .forms import *
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import login, logout, authenticate
from packages.decorators import admin_required, doctor_required, patient_required
from django.utils.decorators import method_decorator
from rest_framework.permissions import IsAuthenticated
from rest_framework import viewsets, status
from .models import *
from .serializers import DoctorAssignmentSerializer,UserSignupSerializer
from .serialzers import * 
from rest_framework import generics, permissions
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.conf import settings
from cryptography.fernet import Fernet
import openai
from datetime import datetime, timedelta
from django.utils.timezone import now
import os



#apis codes
class UserSignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSignupSerializer
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User registered successfully", "user_id": user.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        return Response({
            "message": "Login successful",
            "access": response.data["access"],
            "refresh": response.data["refresh"]
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()  # Blacklist the refresh token
            return Response({"message": "Logout successful"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)



class SecureView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "You are authenticated!"})


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        data['role'] = self.user.role  # Send user role in response
        data['email'] = self.user.email
        return data


class LoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer




class AssignDoctorView(generics.CreateAPIView):
    """Assign a doctor to a patient"""
    serializer_class = DoctorAssignmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        patient = self.request.user
        if patient.role != "Patient":
            return Response({"error": "Only patients can assign a doctor"}, status=400)
        serializer.save(patient=patient)


class PatientDoctorsView(generics.ListAPIView):
    """Retrieve all doctors assigned to a specific patient"""
    serializer_class = DoctorAssignmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return DoctorAssignment.objects.filter(patient=self.request.user)



class DoctorPatientsView(generics.ListAPIView):
    """Retrieve all patients assigned to a specific doctor"""
    serializer_class = DoctorAssignmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return DoctorAssignment.objects.filter(doctor=self.request.user)


def encrypt_text(plaintext):
    key = settings.SECRET_ENCRYPTION_KEY.encode()
    cipher = Fernet(key)
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt_text(encrypted_text):
    key = settings.SECRET_ENCRYPTION_KEY.encode()
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_text.encode()).decode()


class SubmitDoctorNoteView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        #Doctors submit notes for a patient (encrypted)
        doctor = request.user
        patient_id = request.data.get("patient_id")
        raw_notes = request.data.get("notes")

        if not patient_id or not raw_notes:
            return Response({"error": "Patient ID and notes are required."}, status=400)

        patient = get_object_or_404(User, id=patient_id, is_patient=True)
        # Encrypting notes before saving
        encrypted_notes = encrypt_text(raw_notes)
        # Processing note with LLM
        try:
            llm_result = extract_actionable_steps(raw_notes)
            checklist = llm_result.get("checklist", [])
            plan = llm_result.get("plan", [])
        except Exception as e:
            return Response({"error": f"LLM processing failed: {str(e)}"}, status=500)

        # Ensuring old notes are deleted
        DoctorNote.objects.filter(doctor=doctor, patient=patient).delete()
        ActionableStep.objects.filter(note__doctor=doctor, note__patient=patient).delete()

        # Saving new note
        note = DoctorNote.objects.create(doctor=doctor, patient=patient, encrypted_notes=encrypted_notes)
        #saving a new actionable step
        actionable_step = ActionableStep.objects.create(note=note, checklist=checklist, plan=plan)
        #schedule remainders
        schedule_reminders(patient, actionable_step)
        return Response({
            "message": "Note saved successfully!",
            "note_id": note.id,
            "actionable_steps": {
                "checklist": checklist,
                "plan": plan
            }
        }, status=201)


class RetrieveDoctorNoteView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, patient_id):
         #Doctor or patient retrieves notes (decrypted) 
        user = request.user
        patient = get_object_or_404(User, id=patient_id, is_patient=True)

        # Check permissions
        if user.is_patient and user != patient:
            return Response({"error": "Unauthorized"}, status=403)

        if user.is_doctor:
            note = DoctorNote.objects.filter(doctor=user, patient=patient).first()
        else:
            return Response({"error": "Unauthorized"}, status=403)
        
        if not note:
            return Response({"error": "No notes found."}, status=404)

        # Decrypting and returning
        decrypted_notes = decrypt_text(note.encrypted_notes)
        return Response({"patient": patient.full_name, "doctor": note.doctor.full_name, "notes": decrypted_notes})




openai.api_key = settings.OPENAI_API_KEY  #

def extract_actionable_steps(notes):
    """ Calls OpenAI API to extract actionable steps from doctor notes. """
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",  # Use gpt-4 or gpt-3.5-turbo
            messages=[
                {"role": "system", "content": "You are a medical assistant that extracts actionable steps from doctor notes."},
                {"role": "user", "content": f"Extract a checklist (immediate tasks) and a plan (scheduled actions) from these doctor notes: {notes}"}
            ],
            temperature=0.3
        )

        ai_response = response["choices"][0]["message"]["content"]

        # Expecting structured JSON-like response from the LLM
        return json.loads(ai_response)

    except Exception as e:
        return {"error": f"LLM processing failed: {str(e)}"}



class MarkChecklistCompletedView(APIView):
     #Allows patients to mark a checklist item as completed. 
    permission_classes = [IsAuthenticated]

    def post(self, request):
        patient = request.user
        item = request.data.get("task")

        if not item:
            return Response({"error": "Task description is required"}, status=400)
        step = ActionableStep.objects.filter(note__patient=patient).first()
        if not step:
            return Response({"error": "No actionable steps found."}, status=404)
        step.mark_checklist_item_completed(item)
        return Response({"message": f"Checklist task '{item}' marked as completed!"})


class MarkPlanTaskCompletedView(APIView):
    """ Allows patients to check-in and mark scheduled plan tasks as completed. """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        patient = request.user
        task = request.data.get("task")
        if not task:
            return Response({"error": "Task description is required"}, status=400)
        check_in = PatientCheckIn.objects.create(patient=patient)
        check_in.mark_task_completed(task)
        reminder = Reminder.objects.filter(patient=patient, task_description=task, completed=False).first()
        if reminder:
            reminder.mark_completed()
        return Response({"message": f"Scheduled task '{task}' marked as completed!"})



class UpcomingRemindersView(APIView):
    # Retrieving upcoming reminders for a patient. 
    permission_classes = [IsAuthenticated]

    def get(self, request):
        patient = request.user
        reminders = Reminder.objects.filter(patient=patient, completed=False, scheduled_at__gte=now())

        data = [
            {"task": r.task_description, "scheduled_at": r.scheduled_at}
            for r in reminders
        ]

        return Response({"upcoming_reminders": data})


def schedule_reminders(patient, actionable_step):
    """ Creates reminders based on extracted plan. """
    for task in actionable_step.plan:
        for day in range(task["days"]):
            reminder_date = datetime.datetime.now() + datetime.timedelta(days=day)
            Reminder.objects.create(
                patient=patient,
                step=actionable_step,
                task_description=task["task"],
                scheduled_at=reminder_date
            )


class HomePage(View,LoginRequiredMixin):
    template_name = 'index.html'

    def get(self,request):
        return render(request,self.template_name)



class UserSignUp(View):
    template_name = 'signup.html'

    def get(self, request):
        form = SignupForm
        context = {'form': form}
        return render(request, self.template_name, context)


    def post(self,request,*args,**kwargs):
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user_role = form.cleaned_data.get('role')
            user.role = user_role
            user.save()
            messages.success(self.request, f"Account created successfully")
            return redirect('login')
        messages.info(self.request, f"Something went wrong")
        context = {'form':form}
        return render(request, self.template_name,context)


class LoginPageView(FormView):
    template_name = 'login.html'
    form_class = UserLoginForm
    success_url = reverse_lazy('home')

    def dispatch(self, request, *args, **kwargs):
        """Redirect authenticated users to home page."""
        if request.user.is_authenticated:
            messages.info(request, 'You are already logged in.')
            return redirect('home')
        return super().dispatch(request, *args, **kwargs)
    

    def form_valid(self, form):
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']
        user = authenticate(self.request, username=email, password=password)

        if user is not None:
            login(self.request, user)
            messages.success(self.request, 'Login successful.')  
            #Creating a LogEntry for Users Action                
            create_log_entry(
                user=user,
                content_type=ContentType.objects.get_for_model(User),
                object_id=user.pk,
                object_repr=str(user),
                action_flag=2,
                change_message= f"User {user.pk} has logged in successfully"
            )
            
            return super().form_valid(form)
        else:
            messages.error(self.request, 'Invalid credentials!')
            return self.form_invalid(form)



class LogoutView(View):
    def get(self, request):
        if request.user.is_authenticated:
            # Log the logout action
            create_log_entry(
                user=request.user,
                content_type=ContentType.objects.get_for_model(User),
                object_id=request.user.pk,
                object_repr=str(request.user),
                action_flag=2,  # CHANGE action
                change_message=f"User {request.user.pk} has logged out successfully"
            )

        
        logout(request)
        messages.info(request, 'You have successfully logged out.')
        return redirect('login')




class ProfileUpdateView(LoginRequiredMixin, UpdateView):
    model = User
    form_class = AdminUpdateUserForm
    template_name = 'profile_update.html'
    success_url = reverse_lazy('profile')

    def get_object(self):
        return self.request.user
    

    def form_valid(self, form):
        self.object = form.save(commit=False)
        self.object.user = self.request.user
        self.object.save()
         # Log the profile update action
        create_log_entry(
            user=self.request.user,
            content_type=ContentType.objects.get_for_model(User),
            object_id=self.request.user.pk,
            object_repr=str(self.request.user),
            action_flag=2,  # CHANGE action
            change_message=f"User {self.request.user.pk} has successfully updated their profile"
        )
        return super().form_valid(form)
    
    def get_success_url(self):
        messages.success(self.request, f"Profile updated Successfully")
        return reverse('home')
    



@method_decorator([admin_required], name='dispatch')
class AdminRegisterUsersView(CreateView):
    model = User
    template_name = 'admin_create_user.html'
    form_class = AdminRegisterUserForm
    success_message = "User Created Successfully"

    def form_valid(self, form):
       

       email = form.cleaned_data.get('email')

    # Check if email already exists
       if User.objects.filter(email=username).exists():
         messages.error(self.request, "A user with this email already exists. Please choose a different one.")
         return self.form_invalid(form)

       try:
          response = super().form_valid(form)
        
          # Log the user creation
          create_log_entry(
            user=self.request.user,
            content_type=ContentType.objects.get_for_model(User),
            object_id=self.object.pk,
            object_repr=str(self.object),
            action_flag=1,
            change_message=f"Admin {self.request.user} created a new user: {self.object.username}"
           )

          return response

       except IntegrityError:
        messages.error(self.request, "An error occurred while creating the user. The username might already exist.")
        return self.form_invalid(form)


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_name'] = 'create-staff'
        context['list_name'] = 'staff_list'
        return context

    def get_success_url(self):
        return reverse('home')


#admin view all users
@method_decorator(admin_required, name='dispatch')
class AdminUserListView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'management/authentication/user_list.html'
    context_object_name = 'users'
    paginate_by = 10  # Display 10 users per page

    def get_queryset(self):
        return User.objects.all().order_by('-date_joined')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_name'] = 'users_lists'
        context['list_name'] = 'user_lists'
        return context 

#admin view only doctors

@method_decorator(admin_required, name='dispatch')
class AdminDoctorListView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'management/authentication/user_list.html'
    context_object_name = 'users'
    paginate_by = 10  # Display 10 users per page

    def get_queryset(self):
        return User.objects.filter(is_doctor=True).order_by('-id')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_name'] = 'users_lists'
        context['list_name'] = 'user_lists'
        return context 



#admin view all patients
@method_decorator(admin_required, name='dispatch')
class AdminPatientListView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'management/authentication/user_list.html'
    context_object_name = 'users'
    paginate_by = 10  # Display 10 users per page

    def get_queryset(self):
        return User.objects.filter(is_patient=True).order_by('-id')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_name'] = 'users_lists'
        context['list_name'] = 'user_lists'
        return context 


@method_decorator(admin_required, name='dispatch')
class AdminUserDetailView(LoginRequiredMixin, DetailView):
    model = User
    template_name = 'management/authentication/user_details.html'
    context_object_name = 'user'

    # If you're using `user_id` instead of `pk`
    slug_field = 'id'
    slug_url_kwarg = 'id'

#admin update users account
@method_decorator(admin_required, name='dispatch')
class AdminUpdateUserView(LoginRequiredMixin, UpdateView):
    model = User
    form_class = AdminUpdateUserForm
    template_name = 'management/authentication/update_user.html'
    context_object_name = 'user'

    def form_valid(self, form):
        messages.success(self.request, "User account updated successfully.")
        #keeping track of the event
        create_log_entry(
            user=self.request.user,
            content_type=ContentType.objects.get_for_model(User),
            object_id=self.object.pk,
            object_repr=str(self.object),
            action_flag=1,
            change_message=f"Admin {self.request.user} updated : {self.object.username} account"
           )

        return super().form_valid(form)

    def get_success_url(self):
        return reverse('user_details', kwargs={'pk': self.object.pk})
    

    def get_context_data(self,**kwargs):
        context = super().get_context_data(**kwargs)
        context['page_name'] = 'admin_update_account'
        context['list_name'] = 'admin_updates'
        return context



@method_decorator(admin_required, name='dispatch')
class AdminDeleteUserView(LoginRequiredMixin, DeleteView):
    model = User
    template_name = 'management/authentication/delete_user.html'
    context_object_name = 'user'
    success_url = reverse_lazy('admin_user_list')

    def delete(self, request, *args, **kwargs):
       
       user = self.get_object()  # Capture user before deletion
       user_id = user.pk  # Store user ID before deletion
       username = user.username  # Store username before deletion

       response = super().delete(request, *args, **kwargs)  # Perform deletion

      # Log deletion after the user is deleted
       create_log_entry(
        user=self.request.user,
        content_type=ContentType.objects.get_for_model(User),
        object_id=user_id,  # Use stored user ID
        object_repr=username,  # Use stored username
        action_flag=3,  # 3 represents 'deletion' in Django's LogEntry model
        change_message=f"Admin {self.request.user} deleted: {username} account"
       )

       messages.success(request, f"User {user.full_name} deleted successfully.")

       return response


#admin change users password
@method_decorator(admin_required, name='dispatch')
class AdminChangeUserPasswordView(LoginRequiredMixin, FormView):
    template_name = 'management/authentication/change_password.html'
    form_class = AdminChangePasswordForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["user"] = get_object_or_404(User, user_id=self.kwargs["user_id"])
        return context

    def form_valid(self, form):
        user = get_object_or_404(User, id=self.kwargs["id"])
        new_password = form.cleaned_data["new_password"]
        
        # Hash the new password and update the user's record
        user.password = make_password(new_password)
        user.save()
         # Log the Password change action
        create_log_entry(
            user=self.request.user,
            content_type=ContentType.objects.get_for_model(User),
            object_id=user.pk,
            object_repr=str(user),
            action_flag=2,  # UPDATE action
            change_message=f"Admin {self.request.user} changed the password for user {user.username}."
        )

        messages.success(self.request, "User's password updated successfully.")
        return redirect(reverse("admin_user_detail", kwargs={"id": user.id}))







