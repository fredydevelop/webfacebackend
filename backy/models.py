# models.py
from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    date_created= models.DateTimeField(auto_now=True)
    profile_image = models.ImageField(upload_to='profile_images/')

    
    def __str__(self):
        return self.user.email


