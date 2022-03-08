from django.shortcuts import render
from rest_framework.views import APIView,Response
from django.contrib.auth import authenticate, login
from rest_framework.viewsets import GenericViewSet
from rest_framework.permissions import IsAuthenticated
from users.serializers import (
                                RegisterUserSerializer,
                                CreateUserSerializer,
                                BuildingSerializer,
                                GroupSerializer,
                                RetrieveBuildingSerializer
                            )
from rest_framework import serializers
from django.contrib.auth.models import User
from users.models import RoleUser as  UserRole
from users.models import (Role,
                            Building,
                            Group
                            )
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import AllowAny
from rest_framework.generics import GenericAPIView
from rest_framework import viewsets
from django.db.models import Q
from rest_framework import status

# from users.models import RoleUser
import jwt





# Create your views here.
class registration_screen(APIView):
    # create a dictionary to pass
    # data to the template
    def get(self,request):
        return render(request, "register.html")

class user_register(APIView):
    def post(self,request):
        print("kmoooooooooiiiiiiiiiiii")
        print (request.data["username"])
        response = {
            'success':"",
            'data':""
        }
        print("0")
        serializer_object = CreateUserSerializer()  # creating serializer object
        print("1")
        # try:
        #     print("2")
        #     if request.data["username"] is None:
        #         raise ValueError("username field required")
        #     elif request.data["firstname"] is None:
        #         raise ValueError("firstname field required")
        #     elif request.data["lastname"] is None:
        #         raise ValueError("lastname field required")
        #     elif request.data["email"] is None:
        #         raise ValueError("email field required")
        #     elif request.data["password"] is None:
        #         raise ValueError("password field required")
        #     elif request.data["role"] is None:
        #         raise ValueError("role field required")
        #     print("3")
        # except Exception as e :
        #     print("4")
        #     response={'data':e,'success':'false'}
        #     return Response (response)
        print("5")
        # serializer = CreateUserSerializer.create(serializer_object, validated_data=request.data)  # calling the create
        user = User(
                email=(request.data['email']),  # getting the email
                username=request.data['username'],   # getting the username
                first_name=request.data['firstname'],   # getting the firstname
                last_name=request.data['lastname']   # getting the lastname
        )
        print("user",user)
        if User.objects.filter(email=request.data['email']).count() > 0:
            return "email present"
        print("after")
        user.is_active=True  # making the isactive field to False
        user.set_password(request.data['password'])  # setting the password for the user by hashing
        user.save()  # saving the user
        # print("usrrr",usr)
        # print("serializerrrr",serializer.name,serializer.id)
        UserRole.objects.create(
                    user=user,
                    # role=request.data["role"]
                    role=Role.objects.get(name=request.data["role"])
                )
        print("rolee ceated")
        # method to insert data in the User model
        # current_site = get_current_site(request)  # getting the current domain address
        # mail_subject = 'Activate your account.'  # subject of the mail
        # try:
        #     payload = {  # payload to be in included in the token
        #         'email': serializer.email,
        #         'username': serializer.username,
        #         'userid': serializer.id

        #     }
        # except Exception:
        #     response['data']='email already registered'
        #     response['success']='false'
        #     return response
        # token = jwt.encode(payload, 'secret', algorithm='HS256').decode('utf-8')  # generating the token
        # message = render_to_string('FundooApp/account_active_email.html', {
        #     'domain': current_site.domain,
        #     'token': token,
        # })  # generating the message to be send with the email ,rendering the link to account_active_email and giving
        # # payload in url
        # to_email = serializer.email  # getting the email address
        # email = EmailMessage(
        #     mail_subject, message, to=[to_email]  # creating object of EmailMessage class
        # )

        # email.send()  # sending the email
        # response['data']='Please confirm your email address to complete the registration'
        # response['success']='True'
        return render(request, "login.html")


# method used for login of the user by providing username and password
class user_login(APIView):
    def post(self,request):  # allows the user for login

        response = {
            'success': '',
            'data': ''
        }
        username = request.data['username']  # getting the user name

        password = request.data["password"]  # getting the password
        print("username",username)
        print("password",password)
        if username is None or password is None:  # validating whether any of the data is none or not
            response['success']='False'
            response['data']='Please provide both username and password'
            return Response(response)

        user = authenticate(username=username, password=password)  # verifying the user name and password
        print("user after auth",user)
        if not user:
            response['success']='False'
            response['data']='Invalid Credentials'
            return Response(response)  # if not found returning
        role=UserRole.objects.filter(user=user)
        print("role",role)
        print("role",role[0].role.name)
        payload = {
            'id': user.id,
            'username': user.username  # generating payload

        }
        encoded_jwt = jwt.encode(payload, 'secret', algorithm='HS256')  # generating the token
        # redis_key = redisoperations()  # creating the redis object
        # redis_key.set('token', encoded_jwt)  # setting the redis cache key
        from django.core import serializers as core_serializers
        # data = core_serializers.serialize('json',Building.objects.all())
        building_queryset=Building.objects.all()
        serializer_data = RetrieveBuildingSerializer(
                building_queryset, many=True,
            ).data
        # data = RetrieveBuildingSerializer.serialize(Building.objects.all())
        print("data",serializer_data)
        import json
        formatted_data=json.dumps(serializer_data) 
        # print("c",c)
        # temp_dict=data['fields']
        # temp_dict=[{
        #     "pk":1,
        #     "buildingname":"burjdubai",
        #     "group":"emaar"},
        #     {
        #         "pk":2,
        #     "buildingname":"burjkhaliofa",
        #     "group":"dubai"}
        # ]
        response['success']='True'
        response['data']=encoded_jwt
        response['Admin']=True if role[0].role.name == 'Admin' else False
        response['building']=serializer_data
        print("responseee",response)
        # res=[]
        # res.append(response)
        print("res",response)
        return render(request, "dashboard.html",response)# returning the token for the future requirments



class InviteUserViewSet(GenericViewSet):
    permission_classes = (IsAuthenticated,)
    serializer_class = RegisterUserSerializer

    def create(self, request, *args, **kwargs):
        invited_by = request.data.get("invited_by")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        email = data["email"].lower()
        role = data["role"]
        message_list = []
        user = get_user_model().objects.filter(email=email).first()
        if user:
            if not user.is_active:
                user.user_status = UserStatuses.ACTIVE
                user.save()
            else:
                user_roles = UserRoleSerializer(
                    UserRole.objects.filter(user=user).exclude(is_active=False),
                    many=True,
                ).data
                return Response(
                    {
                        "message": "User already Registered with the application",
                        "roleList": user_roles,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # if role.name in [ROLE_ENTERPRISE_ADMIN, ROLE_ENTERPRISE_USER]:
        #     entity_name = data.get("enterprise").name
        # elif role.name in [ROLE_FLEET_MANAGER, ROLE_FLEET_USER, ROLE_DRIVER]:
        #     entity_name = data.get("fleet").name
        # else:
        #     entity_name = "Inshare"

        # user_sender_qs = get_user_model().objects.get(id=request.user.id)
        # invited_by = user_sender_qs.firstname + " " + user_sender_qs.lastname
        # if len(invited_by) <= 1:
        #     invited_by = user_sender_qs.email

        new_user = False
        if not user:
            if role.name in [ROLE_DRIVER]:
                user = get_user_model().objects.create_user(
                    {"email": email, "user_status": UserStatuses.ACTIVE}
                )
            else:
                user = get_user_model().objects.create_user({"email": email})
                invite_user_via_email(user, role.name, entity_name, invited_by)
            new_user = True
        else:
            if user.user_status == UserStatuses.DELETED:
                user.user_status = UserStatuses.ACTIVE
                user.save()
            inform_user_via_email(user, role.name, entity_name, invited_by)
            new_user = True

        if role.name == ROLE_INSHARE_ADMIN:
            if check_user_has_role(user, role):
                message_list.append(f"{email} Already Have {role.name} Role!")
            else:
                UserRole.objects.create(
                    user=user,
                    role=Role.objects.get(name=role.name),
                    is_default=new_user,
                )
        if role.name in [ROLE_ENTERPRISE_ADMIN, ROLE_ENTERPRISE_USER]:
            enterprise = data.get("enterprise")
            if not enterprise:
                return Response(
                    {"message": f"enterprise required to create {role}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # entity_type = ContentType.objects.get(app_label='fleet_management', model='enterprise')
            if check_user_has_role(user, role, entity_obj=enterprise.pk):
                message_list.append(f"{email} Already Have {role.name} Role!")
            else:
                UserRole.objects.create(
                    user=user,
                    role=Role.objects.get(name=role.name),
                    entity_object=enterprise,
                    is_default=new_user,
                )
        if role.name in [ROLE_FLEET_MANAGER, ROLE_FLEET_USER, ROLE_DRIVER]:
            fleet = data.get("fleet")
            if not fleet:
                return Response(
                    {"message": f"fleet required to create {role}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # entity_type = ContentType.objects.get(app_label='fleet_management', model='fleet')
            if check_user_has_role(user, role, entity_obj=fleet.pk):
                message_list.append(f"{email} Already Have {role.name} Role!")
            else:
                UserRole.objects.create(
                    user=user,
                    role=Role.objects.get(name=role.name),
                    entity_object=fleet,
                    is_default=new_user,
                )
                if role.name == ROLE_DRIVER:
                    driver = data.get("driver")
                    if not driver:
                        request.data["user"] = user
                        request.data["driver_email"] = email
                        driver_serializers = DriverSerializer(data=request.data)
                        if driver_serializers.is_valid():
                            driver_serializers.save()
                    else:
                        Driver.objects.filter(id=driver.id).update(
                            user=user, driver_email=email
                        )

        # TODO : do a common implementation
        return Response(
            {
                "code": status.HTTP_200_OK,
                "message": "Invite Sent Successfully! " + " ".join(message_list),
            },
            status=status.HTTP_200_OK,
        )

class login_view(APIView):
    # create a dictionary to pass
    # data to the template
    def get(self,request):
        return render(request, "login.html")



@csrf_exempt
@api_view(["GET"])
@permission_classes((AllowAny,))
def edit(request,id):
    print("inside edittt")
    # object=Details.objects.get(id=id)
    building_queryset=Building.objects.get(id=id)
    serializer_data = RetrieveBuildingSerializer(
                building_queryset
            ).data
    print("serializer_data",serializer_data)
    return render(request,'edit.html',{'object':serializer_data})

@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))   
def update(request,id):
    print("inside update")

    try:
        building_obj = Building.objects.get(pk=id)
    except ObjectDoesNotExist:
        return Response(
            {
                "code": status.HTTP_404_NOT_FOUND,
                "message": "Building doesnot exist",
            },
            status=status.HTTP_404_NOT_FOUND,
        )


    if request.data.get("name"):
        building_obj.name = request.data.get("name")

    if request.data.get("address"):
        building_obj.address = request.data.get("address")

    if request.data.get("country"):
        building_obj.country = request.data.get("country")

    building_obj.save()

    # building_queryset=Building.objects.all()
    # serializer_data = RetrieveBuildingSerializer(
    #             building_queryset, many=True,
    #         ).data

    # role=UserRole.objects.filter(user=user)
    # response['success']='True'
    # response['data']=encoded_jwt
    # response['role']=role[0].role.name
    # response['building']=serializer_data
    # print("responseee",response)
    # res=[]
    # res.append(response)
    # print("res",response)
    # return render(request, "dashboard.html",response)
    print("request.user",request.user)
    return Response(
        {"code": status.HTTP_200_OK, "message": "building updated"},
        status=status.HTTP_200_OK,
    )


    # return Response("hai")


@csrf_exempt
@api_view(["GET"])
@permission_classes((AllowAny,))   
def delete(request,pk):   
        Building.objects.filter(pk=pk).delete()
        return Response(
        {"code": status.HTTP_200_OK, "message": "building deleted"},
        status=status.HTTP_200_OK,
    )


class CreateBuildingViewset(viewsets.GenericViewSet):

    serializer_class = BuildingSerializer
    # permission_classes = (IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        print("inside create buildingg")

        building_obj_duplicate_chk = Building.objects.filter(
            Q(name=request.data['name'])
            # & ~Q(is_active=False)
            # & Q(enterprisetofleetmapping__enterprise=enterprise_id)
        )
        
        if building_obj_duplicate_chk:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "message": "Building already exist",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )   
        import copy
        print("beforeee",Group.objects.filter(name=request.data['group'])[0].id)
        request_copy = copy.copy(request.data)
        request_copy['group']=Group.objects.filter(name=request.data['group'])[0].id
        # request.data['group']=Group.objects.filter(name=request.data['group'])
        print("afteerrr")
        building_serializers = self.get_serializer(data=request_copy)
        print("building_serializers",building_serializers)
        
        if building_serializers.is_valid():
            try:
                building_obj = building_serializers.save()
                print("building_obj",building_obj)

            except IntegrityError:
                return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "message": "building already exist",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        
        else:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "message": str(building_serializers.errors),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response("success")





    # object=Details.objects.get(id=id)
    # form=detailsform(request.POST,instance=object)
    # if form.is_valid:
    #     form.save()
    #     object=Details.objects.all()
    #     return redirect('retrieve')


@csrf_exempt
@api_view(["GET"])
@permission_classes((AllowAny,))
def buildingadd(request):
    print("inside edittt")
    # object=Details.objects.get(id=id)
    return render(request,'createbuilding.html')



@csrf_exempt
@api_view(["GET"])
@permission_classes((AllowAny,))
def groupadd(request):
    print("inside edittt")
    # object=Details.objects.get(id=id)
    return render(request,'creategroup.html')

class CreateGroupViewset(viewsets.GenericViewSet):

    serializer_class = GroupSerializer
    # permission_classes = (IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        print("inside create buildingg")

        group_obj_duplicate_chk = Group.objects.filter(
            Q(name=request.data['name'])
            # & ~Q(is_active=False)
            # & Q(enterprisetofleetmapping__enterprise=enterprise_id)
        )
        if group_obj_duplicate_chk:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "message": "Group already exist",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        group_serializers = self.get_serializer(data=request.data)
        print("building_serializers",group_serializers)
        
        if group_serializers.is_valid():
            try:
                group_obj = group_serializers.save()
                print("building_obj",group_obj)

            except IntegrityError:
                return Response(
                    {
                        "code": status.HTTP_400_BAD_REQUEST,
                        "message": "building already exist",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        
        else:
            return Response(
                {
                    "code": status.HTTP_400_BAD_REQUEST,
                    "message": str(group_serializers.errors),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response("success")


# class user_login(APIView):
#     pass
    # def post(self,request):
    #     if request.method == 'POST':
    #         # Process the request if posted data are available
    #         username = request.POST['username']
    #         password = request.POST['password']
    #         # Check username and password combination if correct
    #         user = authenticate(username=username, password=password)
    #         if user is not None:
    #             # Save session as cookie to login the user
    #             login(request, user)
    #             # Success, now let's login the user.
    #             return render(request, 'ecommerce/user/account.html')
    #         else:
    #             # Incorrect credentials, let's throw an error to the screen.
    #             return render(request, 'ecommerce/user/login.html', {'error_message': 'Incorrect username and / or password.'})
    #     else:
    #         # No post data availabe, let's just show the page to the user.
    #         return render(request, 'ecommerce/user/login.html')



        