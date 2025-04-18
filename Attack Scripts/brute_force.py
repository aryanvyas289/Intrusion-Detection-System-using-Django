import requests

# Target URL
URL = "http://127.0.0.1:8000/login/"

# Number of attempts to simulate
NUM_ATTEMPTS = 10

# Headers to request JSON response
HEADERS = {"Accept": "application/json"}

# Login credentials (intentionally incorrect to trigger brute-force detection)
PAYLOAD = {
    "username": "wrong",
    "password": "user"
}

# Simulate brute-force attempts
for i in range(NUM_ATTEMPTS):
    response = requests.post(URL, data=PAYLOAD, headers=HEADERS)
    print(f"Attempt {i+1}: {response.json()}")

print("Brute-force simulation complete. Check the Django server logs for alerts.")