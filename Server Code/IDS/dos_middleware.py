import psutil
import threading
from django.utils.timezone import now
from scapy.all import sniff, IP, UDP, TCP
from django.core.cache import cache
from .models import DOSDetection
from .views import get_client_ip, log_alert, alerts


class DOSDetectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.request_counts = {}  # For HTTP Flood
        self.connection_times = {}  # For Slowloris
        self.packet_counts = {
            "udp": {},  
            "syn": {},  
            "syn_without_http": {}  
        }
        self.HTTP_Threshold = 500  
        self.UDP_Threshold = 500   
        self.SYN_Threshold = 500   
        self.SLOWLORIS_Threshold = 30  
        self.active_http_ips = set()  
        self.start_network_monitoring()

    def __call__(self, request):
        ip = get_client_ip(request)

        # Track IPs making HTTP requests
        self.active_http_ips.add(ip)

        # HTTP Flood Detection
        self.request_counts.setdefault(ip, 0)
        self.request_counts[ip] += 1
        if self.request_counts[ip] > self.HTTP_Threshold:
            self.log_attack(ip, "HTTP Flood", self.request_counts[ip],
                            f"Excessive HTTP Requests: {self.request_counts[ip]}")
            self.request_counts[ip] = 0

        # Slowloris Detection
        if ip not in self.connection_times:
            self.connection_times[ip] = now()
        else:
            duration = (now() - self.connection_times[ip]).total_seconds()
            if duration > self.SLOWLORIS_Threshold and request.method == "GET":
                self.log_attack(ip, "Slowloris", 0,
                                f"Connection open for {duration:.2f} seconds")
                del self.connection_times[ip]

        response = self.get_response(request)
        if ip in self.connection_times and response.status_code == 200:
            del self.connection_times[ip]  # Connection completed normally
            self.active_http_ips.discard(ip)  # Remove from active HTTP IPs

        return response

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src

            # UDP Flood Detection
            if UDP in packet:
                self.packet_counts["udp"].setdefault(src_ip, 0)
                self.packet_counts["udp"][src_ip] += 1
                if self.packet_counts["udp"][src_ip] > self.UDP_Threshold:
                    self.log_attack(src_ip, "UDP Flood", self.packet_counts["udp"][src_ip],
                                    f"High UDP Packet Rate: {self.packet_counts['udp'][src_ip]}")
                    self.packet_counts["udp"][src_ip] = 0

            # SYN Flood Detection
            if TCP in packet and packet[TCP].flags & 0x02:  
                self.packet_counts["syn"].setdefault(src_ip, 0)
                self.packet_counts["syn"][src_ip] += 1

                # Only count as SYN flood if not part of an HTTP request
                if src_ip not in self.active_http_ips:
                    self.packet_counts["syn_without_http"].setdefault(
                        src_ip, 0)
                    self.packet_counts["syn_without_http"][src_ip] += 1
                    if self.packet_counts["syn_without_http"][src_ip] > self.SYN_Threshold:
                        self.log_attack(src_ip, "SYN Flood",
                                        self.packet_counts["syn_without_http"][src_ip],
                                        f"Excessive SYN Requests: {self.packet_counts['syn_without_http'][src_ip]}")
                        self.packet_counts["syn_without_http"][src_ip] = 0

    def start_network_monitoring(self):
        try:
            monitor_thread = threading.Thread(
                target=lambda: sniff(
                    filter="udp or tcp", 
                    prn=self.packet_callback,
                    store=0
                ),
                daemon=True
            )
            monitor_thread.start()
            print("Network monitoring started")
        except Exception as e:
            print(f"Error starting network monitoring: {e}")

    def log_attack(self, ip, attack_type, traffic_rate, details):
        try:
            attack, created = DOSDetection.objects.get_or_create(
                Attackers_IP=ip,
                Attack_type=attack_type,
                defaults={
                    'Detection_date_and_time': now(),
                    'Traffic_rate': traffic_rate,
                    'Details': details
                }
            )
            if not created:
                attack.update_attack(traffic_rate, details)
            log_alert(
                f"DoS/DDoS {'detected' if created else 'updated'}: {attack_type} from {ip}")
        except Exception as e:
            print(f"Error logging attack: {e}")

    # def start_network_monitoring(self):
    #     threading.Thread(
    #         target=lambda: sniff(prn=self.packet_callback, store=0),
    #         daemon=True
    #     ).start()
