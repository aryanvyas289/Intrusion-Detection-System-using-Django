
from django.contrib import admin
from django.urls import path,include
from IDS.views import *

urlpatterns = [
    path("admin/", admin.site.urls),
    path("",include("IDS.urls")),
]
