# udp_flood_test.py
from scapy.all import IP, UDP, RandShort, send
import random
import time

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8080

# Send more packets to exceed threshold
for i in range(50):  # Reduced iterations but increased packet count
    packets = [
        IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT, sport=RandShort()) / ("X" * random.randint(100, 500))
        for _ in range(50)  # Increased packets per batch
    ]
    send(packets, verbose=0, inter=0.001)  # Reduced delay to 1ms
    print(f"UDP Flood batch {i+1}/50 sent (total packets: {(i+1)*50})")
    time.sleep(0.1)  # Small delay between batches

print("UDP Flood test complete.")