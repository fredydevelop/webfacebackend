
#from django.contrib.auth.decorators import login_required
#from django.contrib.auth.hashers import make_password
#from django.http import JsonResponse
#from django.middleware.csrf import get_token
#import json
#import os
#from face_recognition_function import verify_faces
#from django.middleware.csrf import rotate_token
#from django.views.decorators.cache import never_cache
#rom django.views.decorators.http import require_http_methods
#from django.shortcuts import render, redirect
# import verify_func
#import keras.layers as Layer
#import keras
#import zipfile
# from your_module import L1Dist  # Update with your actual import for L1Dist
import os 
from django.conf import settings
from L1layer import L1Dist
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework.response import Response
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
import tensorflow as tf
import cv2
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from .models import UserProfile
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.utils.decorators import method_decorator
from PIL import Image
import numpy as np
from .Serializer import UserSerializer





def preprocess(image_array):
    img = tf.convert_to_tensor(image_array, dtype=tf.float32)
    img = tf.image.resize(img, (100, 100))
    img = img / 255.0  
    return img


def verify_func(model, input_img, validation_img, verification_threshold):
    input_img = preprocess(input_img)
    validation_img = preprocess(validation_img)

    images = np.array([input_img, validation_img])
    images = np.expand_dims(images, axis=0)

    result = model.predict(list(np.expand_dims([input_img, validation_img], axis=1)))

    verified = result[0] >= verification_threshold

    return verified




class GetUserView(APIView):
    permission_classes = (permissions.AllowAny,)
    def get(self, request, format=None):
        users = User.objects.all()
        users = UserSerializer(users, many=True)

        return Response(users.data)







@method_decorator(csrf_protect, name="dispatch")
class SignupView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        data = self.request.data
        email = data.get("email")
        password = data.get("password")
        password_confirmation = data.get("confirmPassword")
        
        if password != password_confirmation:
            return Response({"error": "Passwords do not match"}, status=400)

        if User.objects.filter(username=email).first():
            return Response({"error": "User already exists"}, status=400)
        
        new_user = User.objects.create_user(username=email,password=password)
        UserProfile.objects.create(user=new_user,profile_image="")
      
        request.session['registration_data'] = {
                'id': new_user.id,
        }
        return Response({"message": "Registration Successful"}, status=200)


@method_decorator(ensure_csrf_cookie, name="dispatch")
class GetCSRFToken(APIView):
    permission_classes = (permissions.AllowAny,)
    def get(self,request,format=None):
        return Response({"message":"CSRF cookie set"})
    


@method_decorator(csrf_protect, name="dispatch")
class UploadImageView(APIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request,format=None):
        user_image = self.request.FILES.get('profile_image')
        if not user_image:
            return Response({"error": "No Image uploaded"})
        user_data = request.session.get("registration_data")
        if not user_data:
            return Response({"error": "Registration data not found in session"})

        id = user_data["id"]
        if not id:
            return Response({"error": "No id Found in session"})

        if User.objects.filter(id=id).exists():  
            new_user = User.objects.get(id=id)
            try:
                new_user_profile = UserProfile.objects.get(user=new_user)
                new_user_profile.profile_image = user_image  # Update the profile image
                new_user_profile.save()  # Save the changes
                del request.session["registration_data"]
                return Response({"message": "Profile image updated successfully"}, status=200)
            except UserProfile.DoesNotExist:
                return Response({"error": "UserProfile not found"}, status=400)
        else:
            return Response({"error": "User with this email does not exist"}, status=400)


class CheckAuthenticatedView(APIView):
    def get(self,request,format=None):
        if (self.request.user.is_authenticated):
            return Response({"isAuthenticated":"success"})
        else:
            return Response({"isAuthenticated": "error"})


@method_decorator(csrf_protect,name="dispatch")
class LoginView(APIView):
    permission_classes=(permissions.AllowAny,)
    def post(self,request,format=None):
        data=self.request.data
        email = data.get("email")
        password = data.get("password")
        if email and password:
            user = authenticate(self.request, username=email, password=password)
            #print(User)
            if user is not None:
                request.session["id"] = user.id
                auth_login(self.request,user)
                return Response({"message": "Login details verified, proceed with face recognition"})
            else:
                return Response({"error": "Invalid login details"}, status=401)
    


@method_decorator(csrf_protect,name="dispatch")
class VerificationView(APIView): 
    def post(self,request,format=None):  
        user_id = self.request.session.get("id")
        if not user_id:
            auth_logout(self.request)
            self.request.session.flush()
            return Response({"error": "User id not found in session"})
        user_image = self.request.FILES.get('profile_image')
        if not user_image:
            auth_logout(self.request)
            self.request.session.flush() 
            return Response({"error": "No image uploaded"})

        user_detail = UserProfile.objects.filter(user__id=user_id).first()
        if not user_detail:
            auth_logout(self.request)
            self.request.session.flush() 
            return Response({"error": "User not found"})

        try:
            db_img_path = user_detail.profile_image.path
            db_picture = cv2.imread(db_img_path)
            db_picture = np.array(db_picture)

            uploaded_image = Image.open(user_image)
            image_array = np.array(uploaded_image)

            model_path = settings.MODEL_PATH
            if not os.path.exists(model_path):
                print("error", "Model file not found")
                return Response({"error": "Model file not found"})
            model = tf.keras.models.load_model(model_path, custom_objects={'L1Dist': L1Dist})
            is_match = verify_func(model, db_picture, image_array, 0.6)
            print(is_match)

            if is_match:
                return Response({"message": "Verification successful"}, status=200)
            else:
                auth_logout(self.request)
                self.request.session.flush()
                return Response({"error": "Face does not match, access denied"})

        except Exception as e:
            return Response({"error": str(e)})
   

class LogoutView(APIView):
    def post(self,request,format=None):
        auth_logout(request)
        request.session.flush()  
        return Response({"message": "Logout successful"}, status=200)
