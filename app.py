from fastapi import FastAPI, UploadFile, File   # FastAPI for API, UploadFile for receiving files
from typing import Dict, List                   # Type hints for dictionaries and lists
import re                                       # Regex library for pattern matching

app = FastAPI()                                 # Create the FastAPI application


@app.get("/health")                             # Simple health-check endpoint
def health():
    return {"status": "ok"}                     


@app.post("/analyze")                           # Main endpoint where log files are analysed
async def analyze(file: UploadFile = File(...)):  # Accept an uploaded file from Streamlit
   
    raw_bytes = await file.read()               # Read the raw bytes from the uploaded file
    lines = raw_bytes.decode(errors="ignore").splitlines()  
                                                # Convert bytes → text → split into each line

    failed_by_ip: Dict[str, int] = {}           # Dictionary to count failed logins per IP
    failed_by_user: Dict[str, int] = {}         # Dictionary to count failed logins per username
    timeline: List[dict] = []                   # Stores all interesting log events in order

    ips_with_failures = set()                   # Set to track IPs that had failed logins first

    suspicious_successes: List[dict] = []       # Stores successful logins that happened after failures

    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"      # Regex pattern to match IPv4 addresses


    # Pattern for failed SSH login lines
    failed_pattern = re.compile(
        rf"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>{ip_pattern})"
    )
    # This extracts:
    #   - user
    #   - ip


    # Pattern for successful SSH login lines
    accepted_pattern = re.compile(
        rf"Accepted password for (?P<user>\S+) from (?P<ip>{ip_pattern})"
    )
    # Also extracts:
    #   - user
    #   - ip


    # Loop through every line in the log file
    for line in lines:

        # ------------------------------
        # 1. FAILED LOGIN DETECTION
        # ------------------------------
        if "Failed password" in line:           # If the line contains a failed login

            m = failed_pattern.search(line)     # Try to match it to the failed login regex
            if not m:
                continue                        # If pattern didn't match, skip it

            user = m.group("user")              # Extract username
            ip = m.group("ip")                  # Extract IP address

            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1  
                                                # Increment failed count for this IP

            failed_by_user[user] = failed_by_user.get(user, 0) + 1  
                                                # Increment failed count for this username

            ips_with_failures.add(ip)           # Add IP to "had failures" set

            # Add this event to the timeline list
            timeline.append({
                "type": "failed_login",
                "ip": ip,
                "user": user,
                "line": line,
            })


        # ------------------------------
        # 2. SUCCESSFUL LOGIN DETECTION
        # ------------------------------
        elif "Accepted password" in line:       # If the line contains a successful login

            m = accepted_pattern.search(line)   # Try to match with success regex
            if not m:
                continue

            user = m.group("user")              # Extract username
            ip = m.group("ip")                  # Extract IP address

            # If this IP had failed attempts before, the success is suspicious
            if ip in ips_with_failures:
                suspicious_successes.append({
                    "ip": ip,
                    "user": user,
                    "line": line,
                })

            # Add this successful login to the timeline
            timeline.append({
                "type": "successful_login",
                "ip": ip,
                "user": user,
                "line": line,
            })


    # ------------------------------
    # 3. BRUTE-FORCE DETECTION
    # ------------------------------
    brute_force_ips = [ip for ip, count in failed_by_ip.items() if count >= 5]
    # If an IP has 5+ failed logins, we mark it as suspicious


    # ------------------------------
    # 4. RETURN EVERYTHING TO STREAMLIT
    # ------------------------------
    return {
        "suspicious_ips": brute_force_ips,          # IPs with 5 or more failures
        "failed_counts": failed_by_ip,              # How many failures per IP
        "failed_by_user": failed_by_user,           # How many failures per username
        "suspicious_successes": suspicious_successes,  # Success after failures (bad sign)
        "timeline": timeline[:50],                  # First 50 interesting events for display
    }
