from django.core.management.base import BaseCommand
from users.models import Role
from users.models import RoleUser as  UserRole
from django.contrib.auth.models import User


ROLES_LIST = [
    "Admin",
    "Supervisor",
    "Manager"
]

class Command(BaseCommand):
    def handle(self, *args, **options):

        # Create roles if not found
        for role in ROLES_LIST:
            if not Role.objects.filter(name=role).exists():
                Role.objects.create(name=role)

        # Create default user if db is empty
        # if UMUser.objects.count() == 0:
        if User.objects.filter(username="admin").count() == 0:
            username = "admin"
            password = "admin"
            # print(f"Creating account for {email}")
            admin = User.objects.create_superuser(username=username, password=password)
            inshare_admin_role_obj = Role.objects.get(name="Admin")
            UserRole.objects.create(
                user=admin, role=inshare_admin_role_obj
            )
