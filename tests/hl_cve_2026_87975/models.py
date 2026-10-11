from django.db import models


class Item(models.Model):
    code = models.CharField(max_length=20, primary_key=True)
    data = models.CharField(max_length=20)


class Owner(models.Model):
    name = models.CharField(max_length=20)


class Profile(models.Model):
    owner = models.OneToOneField(Owner, models.CASCADE, primary_key=True)
    age = models.IntegerField()
