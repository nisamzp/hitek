from rest_framework import serializers
from users.models import Role,Building,Group
from django.contrib.auth.models import User


class RegisterUserSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=200)
    # role = serializers.CharField(max_length=200)
    role = serializers.PrimaryKeyRelatedField(
        required=False, allow_null=True, queryset=Role.objects.all()
    )
    

    def validate(self, attrs):
        return attrs

class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username', 'password','first_name','last_name']
        # extra_kwargs = {'email': {'unique': True}}
    #  method to create an database entry in the User model
    def create(self, validated_data):
        user = User(
                email=(validated_data['email']),  # getting the email
                username=validated_data['username'],   # getting the username
                first_name=validated_data['firstname'],   # getting the firstname
                last_name=validated_data['lastname']   # getting the lastname
        )
        if User.objects.filter(email=validated_data['email']).count() > 0:
            return "email present"
        user.is_active=False  # making the isactive field to False
        user.set_password(validated_data['password'])  # setting the password for the user by hashing
        user.save()  # saving the user
        return user

    #  method to activate the user
    def validate(self,id,email):
        result = {
            'success': False,
            'message': 'Something bad happened',
            'data': {}
        }
        try:
            user=User.objects.get(id=id)  # getting the user through the id
            if user.is_active==False:   # checking whether user is active
                user.is_active=True  # making useractive to true for login purposes
                user.save()  # saving the user
                return Response({'message':'UserACTIVATED'})
            else:
                raise ValueError
        except User.DoesnotExist:
            result.message = 'Invalid user'
            return Response(result)
        except ValueError:
            return Response({"message":"not valid"})


class BuildingSerializer(serializers.ModelSerializer):

    class Meta:
        model = Building

        fields = "__all__"

class GroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group

        fields = "__all__"

class RetrieveBuildingSerializer(serializers.ModelSerializer):
    group = serializers.SerializerMethodField()

    class Meta:
        model = Building
        fields = [
                'pk',
                'name',
                'email',
                'address',
                'phone',
                'group']

    def get_group(self, obj):
        return obj.group.name


