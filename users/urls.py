from django.urls import path, include
# from django.conf.urls import url

# from rest_framework.routers import DefaultRouter
from .views import (login_view,
                    user_login,
                    registration_screen,
                    # user_register
                    user_register,
                    edit,
                    update,
                    delete,
                    CreateBuildingViewset,
                    buildingadd,
                    groupadd,
                    CreateGroupViewset

                    
                    )
app_name = 'hitek' 
from rest_framework.routers import DefaultRouter


router = DefaultRouter(trailing_slash=False)

router.register(r"add/building", CreateBuildingViewset, basename="create_building")
router.register(r"add/group", CreateGroupViewset, basename="create_group")
# router.register(r"/register_user", user_register, basename="register_user")

urlpatterns=[
     path('',login_view.as_view(), name='login'),
      path('logins',user_login.as_view(), name='user_login'),
      path('register',registration_screen.as_view(), name='register'),
      path('userregister',user_register.as_view(), name='user_register'),
      path('edit/<int:id>',edit,name='edit'),
      path('buildingadd',buildingadd,name='building_add'),
      path('groupadd',groupadd,name='group_add'),
      path('update/<int:id>',update,name="update"),
      path('delete_product/<int:pk>', delete,name="delete"),
      path(r"", include(router.urls)),  
]