from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
import uuid 
from django.contrib.auth.models import User
# Create your models here.

class CustomBaseModel(models.Model):  # COMM0N
    created = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated = models.DateTimeField(auto_now=True, null=True, blank=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    class Meta:
        abstract = True

class Role(models.Model):
    name = models.CharField(primary_key=True, max_length=255, editable=False)
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "role"

# class UMUser(AbstractBaseUser, PermissionsMixin):
#     """Custom user class."""

#     USERNAME_FIELD = "email"

#     id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
#     username = models.CharField(max_length=50, blank=True)
#     email = models.EmailField(blank=False, unique=True)
#     firstname = models.CharField("first name", max_length=50, null=True, blank=True)
#     lastname = models.CharField("last name", max_length=50, null=True, blank=True)
#     phone = models.BigIntegerField(verbose_name="phone number", null=True, blank=True)
#     dob = models.DateTimeField(blank=True, null=True)
#     is_staff = models.BooleanField(
#         "staff status",
#         default=False,
#         help_text="Designates whether the user can log into this admin site.",
#     )
#     is_active = models.BooleanField(
#         "active",
#         default=True,
#         help_text="Designates whether this user should be treated as active. "
#         "Deselect this instead of deleting accounts.",
#     )
#     created = models.DateTimeField(auto_now_add=True)
#     created_by = models.CharField(max_length=50, null=True, blank=True)
#     updated = models.DateTimeField(auto_now=True)
#     updated_by = models.CharField(max_length=50, null=True, blank=True)
    
#     class Meta:
#         db_table = "um_user"
#         verbose_name = "user"
#         verbose_name_plural = "users"


# class UsersRole(models.Model):
#     user = models.ForeignKey(
#         User, null=False, blank=False, on_delete=models.DO_NOTHING
#     )
#     role = models.CharField("role", max_length=50, null=True, blank=True)

    # role = models.ForeignKey(Role, null=False, blank=False, on_delete=models.DO_NOTHING)



class UsersRole(models.Model):
    user = models.ForeignKey(
        User, null=False, blank=False, on_delete=models.DO_NOTHING
    )
    role = models.CharField("role", max_length=50, null=True, blank=True)


class RoleUser(models.Model):
    user = models.ForeignKey(
        User, null=False, blank=False, on_delete=models.DO_NOTHING
    )
    roles = models.CharField("role", max_length=50, null=True, blank=True)
    role = models.ForeignKey(Role, null=False, blank=False, on_delete=models.DO_NOTHING,default='Supervisor')
    


class Group(models.Model):
    name = models.CharField("role", max_length=50, null=True, blank=True)

    class Meta:
        db_table = "group"



class Building(models.Model):
    group= models.ForeignKey(
        Group, null=False, blank=False, on_delete=models.DO_NOTHING
        )
    name = models.CharField(max_length=50, blank=True)
    email = models.EmailField(blank=False, unique=True)
    address = models.CharField("address", max_length=50, null=True, blank=True)
    country = models.CharField("country", max_length=50, null=True, blank=True)
    phone = models.BigIntegerField(verbose_name="phone number", null=True, blank=True)


    class Meta:
        db_table = "building"

