from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password
from django.conf import settings
from cryptography.fernet import Fernet
from packages.integerId import IntegerIDField
from django.urls import reverse
import base64
from packages.utils import extract_actionable_steps

ROLES = (
    ('Doctor','doctor'),
    ('Patient','patient'),
)

ID_TYPES = [
    ("Driver License", "Driver License"),
    ("Passport", "Passport"),
    ("Ghana Card", "Ghana Card"),
    ("Voter ID", "Voter ID"),
    ]

GENDER = [
    ("Male", "Male"), 
    ("Female", "Female"),
    ]




# Create your models here.
class User(AbstractUser):
    id = IntegerIDField(unique=True, editable=False, primary_key=True)
    full_name = models.CharField(max_length=60, null=True, blank=True)
    phone_number = models.CharField(max_length=20, blank=False, null=True)
    address = models.CharField(max_length=255, blank=False, null=True)
    email = models.EmailField(blank=False, null=True, unique=True)
    date_of_birth = models.DateField(null=True, blank=True)
    emergency_contact_name = models.CharField(max_length=60, null=True, blank=True)
    emergency_contact_phone = models.CharField(max_length=20, null=True, blank=True)
    emergency_contact_relationship = models.CharField(max_length=60, null=True, blank=True)
    emergency_contact_location = models.CharField(max_length=200, null=True, blank=True)
    role = models.CharField(max_length=100, choices = ROLES, default='Patient', null=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    location = models.CharField(max_length=255, null=True, blank=True)
    occupation = models.CharField(max_length=255, null=True, blank=True)
    specialization = models.CharField(max_length=200, null=True, blank=True)
    gender = models.CharField(max_length=10, choices=GENDER, default="Male")
    photo = models.ImageField(null=True,upload_to="users/photos/")
    id_type = models.CharField(max_length=200, choices=ID_TYPES, default="Ghana Card")
    id_number = models.CharField(max_length=50, unique=True,null=True)
    id_front_view = models.ImageField(upload_to='kyc/id_front/', null=True, blank=True)
    id_back_view = models.ImageField(upload_to='kyc/id_back/', null=True, blank=True)

    is_doctor = models.BooleanField(default=False)
    is_patient = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_worker = models.BooleanField(default=False)

    bio = models.TextField(null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'






class DoctorAssignment(models.Model):
    id = IntegerIDField(unique=True, editable=False, primary_key=True)  # Custom ID
    patient = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name="assigned_doctor"
    )
    doctor = models.ForeignKey(User,
        on_delete=models.CASCADE, 
        related_name="patients"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('patient', 'doctor')  # A patient can only have one doctor
        verbose_name = "Doctor Assignment"
        verbose_name_plural = "Doctor Assignments"

    def __str__(self):
        return f"{self.patient.full_name} → {self.doctor.full_name}"


class DoctorNote(models.Model):
    doctor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="doctor_notes")
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="patient_notes")
    encrypted_notes = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        """ Ensure only one note exists per doctor-patient pair (delete old note) """
        DoctorNote.objects.filter(doctor=self.doctor, patient=self.patient).delete()
        super().save(*args, **kwargs)

        #  Trigger LLM processing after saving
        self.process_actionable_steps()

    
    def encrypt_notes(self, plaintext):
        # Encrypting user notes  before saving 
        key = settings.SECRET_ENCRYPTION_KEY.encode()  
        cipher = Fernet(key)
        self.encrypted_notes = cipher.encrypt(plaintext.encode()).decode()

    

    def decrypt_notes(self):
        #Decrypting notes for only  doctor & patient to see
        key = settings.SECRET_ENCRYPTION_KEY.encode()
        cipher = Fernet(key)
        return cipher.decrypt(self.encrypted_notes.encode()).decode()


    def process_actionable_steps(self):
        """ 🔹 Call LLM to generate actionable steps """
        
        extract_actionable_steps(self)

class ActionableStep(models.Model):
    note = models.OneToOneField(DoctorNote, on_delete=models.CASCADE, related_name="actionable_steps")
    checklist = models.JSONField(default=list)  
    plan = models.JSONField(default=list)  
    completed_checklist = models.JSONField(default=list, blank=True) 
    created_at = models.DateTimeField(auto_now_add=True)

    def mark_checklist_item_completed(self, item):
        # Mark a checklist item as completed. 
        if item in self.checklist and item not in self.completed_checklist:
            self.completed_checklist.append(item)
            self.save()

    def __str__(self):
        return f"Steps for {self.note.patient.full_name} (Doctor: {self.note.doctor.full_name})"



class Reminder(models.Model):
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="reminders")
    step = models.ForeignKey(ActionableStep, on_delete=models.CASCADE, related_name="reminders")
    task_description = models.TextField()
    scheduled_at = models.DateTimeField()
    completed = models.BooleanField(default=False)

    def mark_completed(self):
        self.completed = True
        self.save()

    def __str__(self):
        return f"Reminder for {self.patient.full_name} at {self.scheduled_at}"


class PatientCheckIn(models.Model):
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="check_ins")
    timestamp = models.DateTimeField(auto_now_add=True)
    completed_tasks = models.JSONField(default=list)  # Stores completed actions

    def mark_task_completed(self, task):
        # Mark a scheduled task as completed. 
        if task not in self.completed_tasks:
            self.completed_tasks.append(task)
            self.save()

    def __str__(self):
        return f"Check-in for {self.patient.full_name} at {self.timestamp}"




