from django.contrib import admin
from .models import *
from import_export.admin import ImportExportActionModelAdmin


admin.site.site_header= "Aryan's IDS Admin Panel"
admin.site.site_title="Aryan's IDS Admin Panel"
admin.site.index_title="Welcome to Aryan's IDS' Admin Panel"


@admin.register(BruteForceDetection)
class BruteForceDetectionView(ImportExportActionModelAdmin,admin.ModelAdmin):
    list_display=['Detection_date_and_time','Attackers_IP','Number_of_attempts']
    search_fields=['Detection_date_and_time','Attackers_IP','Number_of_attempts']
    list_filter=['Detection_date_and_time','Attackers_IP']


@admin.register(SQLInjectionDetection)
class SQLInjectionDetectionView(admin.ModelAdmin):
    list_display = ["Detection_date_and_time", "Attackers_IP", "attempted_username", "attempted_password"]
    search_fields = ["Attackers_IP", "attempted_username"]
    list_filter = ["Detection_date_and_time","Attackers_IP"]

@admin.register(DOSDetection)
class DOSDetectionView(admin.ModelAdmin):
    list_display=["Detection_date_and_time","Attackers_IP","Attack_type","Traffic_rate","Details"]
    search_fields=["Attackers_IP","Attack_type"]
    list_filter=["Detection_date_and_time","Attackers_IP","Attack_type"]