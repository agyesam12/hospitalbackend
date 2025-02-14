from django import forms  
from django.contrib.auth.forms import AuthenticationForm, UserChangeForm, PasswordChangeForm, UserCreationForm
from .models import User
from django.forms import ModelForm
from django import forms
from .models import *



class UserLoginForm(forms.Form):
    email = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Your Email'}),
        label="User Email"
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter password','autocomplete':'off'}),
        label="Password"
    )


#user signup forms
class SignupForm(UserCreationForm): 
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter password', 'autocomplete':'off'})
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm password', 'autocomplete':'off'})
    )

     # Checking for already existing mails...
    def clean_email(self):
        username = self.cleaned_data.get('username')
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exclude(username=username).count():
            raise forms.ValidationError('This email is already in use! Try another email.')
        return email
    
    

    class Meta:
        model = User
        fields = ['full_name','email','password1', 'password2','role']

        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter email', 'autocomplete':'off'}),
        }


class AdminRegisterUserForm(UserCreationForm):
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter password', 'autocomplete': 'off'})
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm password', 'autocomplete': 'off'})
    )

    class Meta:
        model = User
        fields = [
            'full_name', 'email', 'phone_number',  'country', 'location', 'occupation', 'date_of_birth',
            'gender', 'photo', 'id_type', 'id_number', 'id_front_view', 'id_back_view', 'specialization', 'emergency_contact_phone','emergency_contact_location','emergency_contact_relationship',
             'password1', 'password2', 'is_doctor', 'is_patient', 'is_worker', 'is_admin','bio'
        ]
        widgets = {
            'full_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
            'country': forms.TextInput(attrs={'class': 'form-control'}),
            'location': forms.TextInput(attrs={'class': 'form-control'}),
            'occupation': forms.TextInput(attrs={'class': 'form-control'}),
            'date_of_birth': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'gender': forms.Select(attrs={'class': 'form-control'}),
            'photo': forms.FileInput(attrs={'class': 'form-control'}),
            'id_type': forms.Select(attrs={'class': 'form-control'}),
            'id_number': forms.TextInput(attrs={'class': 'form-control'}),
            'id_front_view': forms.FileInput(attrs={'class': 'form-control'}),
            'id_back_view': forms.FileInput(attrs={'class': 'form-control'}),
            'nok_name': forms.TextInput(attrs={'class': 'form-control'}),
            'nok_phone': forms.TextInput(attrs={'class': 'form-control'}),
            'nok_location': forms.TextInput(attrs={'class': 'form-control'}),
        }
