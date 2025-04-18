from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("", views.dashboard_view, name="dashboard"),
    path("brute-force/", views.brute_force_view, name="brute_force"),
    path("logout/", views.logout_view, name="logout"),
    path('sql-injection/', views.sql_injection_view, name='sql_injection'),
    path('dos-detection/',views.dos_detection_view,name="dos-detection")
]


