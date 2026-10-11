from django.db import models


class CustomPrimaryKey(models.Model):
    my_pk = models.CharField(max_length=10, primary_key=True)
    some_field = models.CharField(max_length=100)

    class Meta:
        app_label = "hl_cve_2026_87975"
