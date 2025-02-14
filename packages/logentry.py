from django.contrib.admin.models import LogEntry
from django.contrib.contenttypes.models import ContentType
from datetime import datetime
from django.utils import timezone

def create_log_entry(user, content_type, object_id, object_repr, action_flag, change_message, action_time=None):
    if action_time is None:
        action_time = timezone.now()

    LogEntry.objects.create(
        user=user,
        content_type=content_type,
        object_id=str(object_id),  # Ensure object_id is stored as a string
        object_repr=object_repr,
        action_flag=action_flag,
        change_message=change_message,
        action_time=action_time
    )





