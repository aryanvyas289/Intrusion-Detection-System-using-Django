# Django IDS Project

A college project to detect insider threats using Django,Python . One of the first Django-based IDS on GitHub!

## Features
- Real-time threat detection
- Web login page
- Admin dashboard
- SQL Injection, DOS/DDOS Detection, Brute Force Detection 
- Intermediate Level UI (Will keep Improving and Updating)
- Report Generation using command:
    "python manage.py excel --attack (attack type) --date (particular date)"

    For example:
    "python manage.py excel --attack SQLInjection --date 2025-03-10"

    Output:
    "Report saved: sqlinjection_report_2025-03-10.xlsx"

    Functionalities:
    1) "All" - Generates report for all kinds of attacks for that date in different sheets in the same File
    2) "SQLInjection" - Generates report for SQL injection only.
    3) "DOS" - Generates report for DOS/DDOS Detection.
    4) "BruteForce" - Generates report for Brute force attack.

## License
MIT License