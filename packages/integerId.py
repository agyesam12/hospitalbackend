import random
from django.db import models
import string
import secrets


def uniqueID():
    """Generate a secure, unique 16-character alphanumeric ID."""
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))


class IntegerIDField(models.CharField):
    """Custom ID field for models."""
    def __init__(self, *args, **kwargs):
        kwargs['unique'] = True
        kwargs['default'] = uniqueID  
        kwargs['max_length'] = 16
        kwargs['db_index'] = True
        super().__init__(*args, **kwargs)



