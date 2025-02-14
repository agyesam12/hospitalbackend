import functools
from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps
from django.utils import timezone



def admin_required(view_func, denied_url="home"):
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.is_admin:
            return view_func(request, *args, **kwargs)
        messages.warning(request, "The requested url is not found on the server, Contact Administrator for help!")
        return redirect(denied_url)  
    return wrapper


def doctor_required(view_func, denied_url="home"):
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if (request.user.is_authenticated and request.user.is_doctor) or (request.user.is_authenticated and request.user.is_admin):
            return view_func(request, *args, **kwargs)
        messages.info(request, "Page not found")
        return redirect(denied_url)  
    return wrapper



def closing_time(view_func, denied_url="closing_time"):
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        current_time = timezone.now().time()
        # Check if the current time is between 00:00 AM and 06:00 AM
        time = (current_time <= timezone.datetime.strptime('00:00', '%H:%M').time() or current_time > timezone.datetime.strptime('06:00', '%H:%M').time())
        if (request.user.is_authenticated and time==True) or request.user.is_admin:
            return view_func(request, *args, **kwargs)
        else:
            messages.info(request, "Work is Closed")
            return redirect(denied_url) 
    return wrapper


