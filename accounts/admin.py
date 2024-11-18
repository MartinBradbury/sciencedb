from django.contrib import admin
from .models import *
from .forms import *
from django.contrib.auth.admin import UserAdmin

@admin.register(CustomUser)
class CustomAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm

    model = CustomUser

