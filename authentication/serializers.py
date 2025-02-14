from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from .models import User,DoctorAssignment
from .models import *

class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ['full_name', 'email', 'password', 'role']

        def create(self, validated_data):
           role = validated_data.pop('role', 'Patient')  # Default to 'Patient' if not provided
           is_doctor = role.lower() == 'doctor'
           is_patient = role.lower() == 'patient'
           user = User.objects.create(
            full_name=validated_data['full_name'],
            email=validated_data['email'],
            is_doctor=is_doctor,
            is_patient=is_patient
        )
           user.set_password(validated_data['password'])  # Hash the password
           user.save()
           return user


        
        




class DoctorAssignmentSerializer(serializers.ModelSerializer):
    patient_name = serializers.CharField(source="patient.full_name", read_only=True)
    doctor_name = serializers.CharField(source="doctor.full_name", read_only=True)

    class Meta:
        model = DoctorAssignment
        fields = ["id", "patient", "doctor", "patient_name", "doctor_name", "created_at"]
        read_only_fields = ["created_at"]


class DoctorNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = DoctorNote
        fields = ["id", "doctor", "patient", "encrypted_notes", "created_at"]





class ActionableStepSerializer(serializers.ModelSerializer):
    """ Serializer for Actionable Steps (Checklist & Plan) """

    class Meta:
        model = ActionableStep
        fields = ["id", "note", "checklist", "completed_checklist", "plan", "created_at"]
        read_only_fields = ["id", "created_at"]

    def update(self, instance, validated_data):
        """ Custom update method to allow marking checklist items as completed. """
        completed_checklist = validated_data.get("completed_checklist", instance.completed_checklist)

        if isinstance(completed_checklist, list):
            instance.completed_checklist = completed_checklist

        instance.save()
        return instance


class ReminderSerializer(serializers.ModelSerializer):
    """ Serializer for Patient Reminders """

    class Meta:
        model = Reminder
        fields = ["id", "patient", "step", "task_description", "scheduled_at", "completed"]
        read_only_fields = ["id", "patient", "step", "scheduled_at", "completed"]


class PatientCheckInSerializer(serializers.ModelSerializer):
    """ Serializer for Patient Check-ins """

    class Meta:
        model = PatientCheckIn
        fields = ["id", "patient", "timestamp", "completed_tasks"]
        read_only_fields = ["id", "timestamp"]

    def update(self, instance, validated_data):
        """ Allows marking tasks as completed """
        completed_tasks = validated_data.get("completed_tasks", instance.completed_tasks)

        if isinstance(completed_tasks, list):
            instance.completed_tasks = completed_tasks

        instance.save()
        return instance

             






