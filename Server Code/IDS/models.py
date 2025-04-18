from django.db import models
from django.utils.timezone import now, timedelta

class BruteForceDetection(models.Model):
    Detection_date_and_time = models.DateTimeField(default=now)  
    Attackers_IP = models.GenericIPAddressField()
    attempted_username = models.CharField(max_length=255, default="blank")
    attempted_password = models.CharField(max_length=255, default="blank")
    Number_of_attempts = models.IntegerField(default=1)  # Accumulate attempts

    @classmethod
    def log_attempt(cls, ip, username, password):
        time_threshold = now() - timedelta(hours=24) 
        attempt = cls.objects.filter(
            Attackers_IP=ip, 
            attempted_username=username, 
            Detection_date_and_time__gte=time_threshold
        ).order_by('-Detection_date_and_time').first()

        if attempt:
            attempt.Number_of_attempts += 1
            attempt.Detection_date_and_time = now()  
            attempt.save()
        else:
            cls.objects.create(Attackers_IP=ip, attempted_username=username, attempted_password=password, Number_of_attempts=1)

    def __str__(self):
        return f"{self.Attackers_IP} - {self.Number_of_attempts} attempts"


class SQLInjectionDetection(models.Model):
    Detection_date_and_time = models.DateTimeField(default=now)
    Attackers_IP = models.CharField(max_length=50)
    attempted_username = models.CharField(max_length=255, default="blank")
    attempted_password = models.CharField(max_length=255, default="blank")
    # Injection_Attempt = models.TextField(default="N/A")

    def __str__(self):
        return f"SQL Injection from {self.Attackers_IP} at {self.Detection_date_and_time}"
    
class DOSDetection(models.Model):
    Detection_date_and_time = models.DateTimeField(default=now)
    Attackers_IP = models.CharField(max_length=50, null=True)
    Attack_type = models.CharField(max_length=75, null=True)
    Traffic_rate = models.FloatField(null=True)
    Details = models.TextField(null=True)

    class Meta:
        unique_together = ('Attackers_IP', 'Attack_type')
        verbose_name = "DoS Detection"
        verbose_name_plural = "DoS Detections"

    def __str__(self):
        return f"{self.Attack_type} from {self.Attackers_IP} at {self.Detection_date_and_time}"  # Fixed

    def update_attack(self, traffic_rate, details):
        """Update existing attack with new traffic rate and details."""
        self.Traffic_rate = traffic_rate  # Fixed
        self.Details = details  # Fixed
        self.Detection_date_and_time = now()  # Fixed
        self.save()
