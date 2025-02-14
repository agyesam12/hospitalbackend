from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password
from django.conf import settings
#from cryptography.fernet import Fernet
from packages.integerId import IntegerIDField
from django.urls import reverse

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




#class DoctorNote(models.Model):
    #doctor = models.ForeignKey("User", on_delete=models.CASCADE, related_name="notes")
    #patient = models.ForeignKey("User", on_delete=models.CASCADE, related_name="patient_notes")
    #encrypted_notes = models.TextField()
    #created_at = models.DateTimeField(auto_now_add=True)

    #def encrypt_notes(self, plaintext):
        """Encrypts doctor notes using Fernet encryption"""
        #cipher = Fernet(settings.SECRET_ENCRYPTION_KEY.encode())
       # self.encrypted_notes = cipher.encrypt(plaintext.encode()).decode()

    #def decrypt_notes(self):
        """Decrypts and returns the original note text"""
        #cipher = Fernet(settings.SECRET_ENCRYPTION_KEY.encode())
        #return cipher.decrypt(self.encrypted_notes.encode()).decode()

    #def save(self, *args, **kwargs):
        """Ensure notes are encrypted before saving"""
        #if not self.encrypted_notes:
            #raise ValueError("Cannot save an empty note")
        #super().save(*args, **kwargs)

