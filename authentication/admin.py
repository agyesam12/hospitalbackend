from django.contrib import admin
from .models import *
from django.contrib.admin.models import LogEntry

# Register your models here.
admin.site.register(User),
admin.site.register(LogEntry)
