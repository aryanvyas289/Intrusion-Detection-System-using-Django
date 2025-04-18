from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.utils.timezone import now
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
import re
import urllib.parse 
from .models import *


THRESHOLD = 5  
MAX_GENUINE_ATTEMPTS = 3  

alerts = []
failed_attempts = {}

def get_client_ip(request): #GET IPS OF CLIENTS OR HACKERS
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR")

def is_sql_injection(query):
    if not isinstance(query, str) or not query:
        return False

    # Decode URL-encoded input to catch encoded attacks (e.g., %27 for ')
    decoded_query = urllib.parse.unquote(query)

    normalized_query = " ".join(decoded_query.split()).lower()

    # Comprehensive list of SQL injection patterns
    sql_patterns = [
        # Basic SQL keywords and syntax
        r"\bselect\b.*\bfrom\b",           # SELECT ... FROM
        r"\binsert\b.*\binto\b",           # INSERT INTO
        r"\bupdate\b.*\bset\b",            # UPDATE ... SET
        r"\bdelete\b.*\bfrom\b",           # DELETE FROM
        r"\bdrop\b.*\btable\b",            # DROP TABLE
        r"\btruncate\b.*\btable\b",        # TRUNCATE TABLE
        r"\balter\b.*\btable\b",           # ALTER TABLE
        
        # Common SQL injection payloads
        r"['\"];?\s*--",                   # Single quote or double quote followed by comment (e.g., ' --)
        r"['\"];?\s*/\*.*\*/",             # Inline comments (e.g., ' /* comment */)
        r"\bunion\b.*\bselect\b",          # UNION SELECT
        r"\bexec\b.*\b[\w_]+\b",          # EXEC procedure_name
        r"\bwaitfor\b.*\bdelay\b",         # WAITFOR DELAY (time-based blind SQLi)
        
        # Tautologies and logical manipulations
        r"1\s*=\s*1",                      # 1=1
        r"1\s*<\s*2",                      # 1<2
        r"or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]",  # OR 'x'='x'
        
        # Encoded or obfuscated attempts
        r"char\s*\(\s*\d+\s*\)",           # CHAR(39) for single quote
        r"concat\s*\(",                    # CONCAT function
        r"0x[0-9a-f]+",                    # Hexadecimal encoding (e.g., 0x27 for ')
        
        # Advanced payloads
        r"\bload_file\b\s*\(",             # LOAD_FILE()
        r"\binto\b\s*\boutfile\b",         # INTO OUTFILE
        r"\bcase\b.*\bwhen\b",             # CASE WHEN (conditional injection)
        r"\bsubstring\b\s*\(",             # SUBSTRING (data extraction)
        r"\bsleep\b\s*\(\s*\d+\s*\)",      # SLEEP() for blind SQLi
        
        # Generic suspicious patterns
        r"[;|$&|]\s*[a-zA-Z]+",            # Semicolon or shell operators followed by commands
        r"[\w\s]*[\|\&]{2}",               # Double pipe or ampersand (|| or &&)
    ]

    #Check for matches in both decoded and normalized input
    for pattern in sql_patterns:
        if re.search(pattern, decoded_query, re.IGNORECASE) or re.search(pattern, normalized_query):
            return True

    #Check for suspicious character combinations
    suspicious_chars = [
        r"['\"][\s]*(?:or|and)[\s]*['\"]",  # ' OR ', " AND "
        r"\b\d+\s*[+\-*/]\s*\d+\b",        # Arithmetic operations (e.g., 1+1)
        r"(?:['\"])\s*\d+\s*(?:['\"])",    # Quoted numbers (e.g., '1')
    ]
    for pattern in suspicious_chars:
        if re.search(pattern, normalized_query):
            return True

    # Check for encoded keywords(e.g., %53%45%4C%45%43%54 for SELECT)
    hex_pattern = r"%[0-9a-fA-F]{2}"
    if re.search(hex_pattern, query):
        hex_decoded = urllib.parse.unquote(query).lower()
        if any(keyword in hex_decoded for keyword in ["select", "union", "drop", "insert"]):
            return True

    return False

def log_alert(message):
    """Log security alerts with timestamp."""
    timestamp = now().strftime("%Y-%m-%d %H:%M:%S")
    alerts.append(f"{timestamp} - {message}")
    print(f"ALERT: {message}")

@csrf_exempt
def login_view(request):
    """Handle login page display and authentication."""
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "GET":
        return render(request, "login.html")

    if request.method == "POST":
        ip = get_client_ip(request)
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")

        is_json_request = request.headers.get("Accept") == "application/json"

        sql_attempt = username if is_sql_injection(username) else password if is_sql_injection(password) else None
        if sql_attempt:
            SQLInjectionDetection.objects.create(
                Detection_date_and_time=now(),
                Attackers_IP=ip,
                attempted_username=username,
                attempted_password=password
            )
            log_alert(f"SQL Injection attempt detected from {ip}")
            if is_json_request:
                return JsonResponse({"error": "Suspicious input detected"}, status=400)
            return redirect("login")

        # Initialize failed attempts for this IP
        if ip not in failed_attempts:
            failed_attempts[ip] = []

        #Authentication
        user = authenticate(username=username, password=password)
        if user is None:
            failed_attempts[ip].append(now())
            num_attempts = len(failed_attempts[ip])

            #AFTER 3 GENUINE ATTEMPTS (GO GET HIM BOY!)
            if num_attempts > MAX_GENUINE_ATTEMPTS:
                BruteForceDetection.objects.create(
                    Detection_date_and_time=now(),
                    Attackers_IP=ip,
                    Number_of_attempts=num_attempts - MAX_GENUINE_ATTEMPTS,  # Start counting from 1 after 3rd attempt
                    attempted_username=username,
                    attempted_password=password,
                )

            if num_attempts > THRESHOLD:
                log_alert(f"Possible brute-force attack detected from {ip}")

            if is_json_request:
                return JsonResponse({"error": "Invalid credentials!"}, status=401)
            return render(request, "login.html", {"error": "Invalid credentials!"})

        if ip in failed_attempts:
            del failed_attempts[ip]  # Clear attempts on success
        login(request, user)
        if is_json_request:
            return JsonResponse({"message": "Login successful"}, status=200)
        return redirect("dashboard")

@login_required
def dashboard_view(request):
    return render(request, "dashboard.html", {"alerts": alerts})

@login_required
def brute_force_view(request):
    attempts = BruteForceDetection.objects.all().order_by("-Detection_date_and_time")
    return render(request, "brute_force.html", {"brute_force_attempts": attempts})

@login_required
def sql_injection_view(request):
    attempts = SQLInjectionDetection.objects.all().order_by("-Detection_date_and_time")
    return render(request, "sql-injection.html", {"attempts": attempts})

@login_required
def logout_view(request):
    logout(request)
    return redirect("login")

@login_required
def dos_detection_view(request): 
    dos_attempts = DOSDetection.objects.all().order_by("-Detection_date_and_time")
    return render(request, "dos-detection.html", {"Traffic_rate": dos_attempts})