from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from .models import User

class SignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
             'id',
            'full_name',
            'email',
            'password',
            'role',

        ]
        extra_kwargs = {"password":{"write_only":True}}

        def validate(self, data):
           if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
           return data

        
        def create(self, validated_data):
         user = User.objects.create_user(**validated_data)
         return user
             






