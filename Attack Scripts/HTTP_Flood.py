# http_flood_test.py
import requests
import threading

URL = "http://127.0.0.1:8080/"
    
def send_requests():
    for _ in range(50):
        try:
            requests.get(URL, timeout=5)  # Added timeout to avoid hanging
            print(f"HTTP request sent from {threading.current_thread().name}")
        except Exception as e:
            print(f"HTTP Flood error: {e}")

threads = []
for _ in range(10):
    t = threading.Thread(target=send_requests)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("HTTP Flood test complete.")  