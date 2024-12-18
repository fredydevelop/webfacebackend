from django.urls import path, re_path
from .views import GetCSRFToken,SignupView,UploadImageView,LoginView,GetUserView,CheckAuthenticatedView,LogoutView,VerificationView
 

urlpatterns= [ 
  path("newaccount/", SignupView.as_view(), name="newaccount"),
  path("csrf-token/", GetCSRFToken.as_view(), name="csrf-token"),
  path("upload_image/",UploadImageView.as_view(),name="upload_image"),
  path("signin/", LoginView.as_view(), name= "login"),
  path("check-users/",GetUserView.as_view(), name="getuser"),
  path('check_auth/', CheckAuthenticatedView.as_view(), name='check_auth'),
  path('logout/', LogoutView.as_view(), name="logout"),
  path('check_owner/', VerificationView.as_view(), name='check_owner'),
]

