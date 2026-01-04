import streamlit as st                 # Streamlit for the frontend web interface
import requests                        # To send log files to the FastAPI backend
import pandas as pd                   # To display results as tables

# Backend API endpoint that will analyze the logs
BACKEND_URL = "http://localhost:8001/analyze"


# ---- PAGE SETUP ----
st.set_page_config(
    page_title="SSH Log Analysis Dashboard",   # Browser tab title
    layout="wide"                              # Use full screen width
)

st.title("SSH Log Analysis Dashboard")         # Main page heading
st.write(
    "This tool analyses SSH/auth log files to find IP addresses with repeated "
    "failed logins and possible brute-force behaviour."     # Short intro description
)


# ---- SIDEBAR ----
st.sidebar.header("Upload log file")           # Sidebar title

# File upload control (only allows .log or .txt)
uploaded = st.sidebar.file_uploader(
    "Choose a .log or .txt file",
    type=["log", "txt"]
)

# Button to start analysis
analyze_btn = st.sidebar.button("Analyze")


# ---- MAIN CONTENT ----
if uploaded and analyze_btn:                   # Only run analysis when user uploads AND clicks button
    st.info(f"Analyzing file: **{uploaded.name}**")

    # Prepare file data to send to backend
    files = {"file": (uploaded.name, uploaded.getvalue())}

    try:
        resp = requests.post(BACKEND_URL, files=files)   # Send file to backend API
        data = resp.json()                               # Parse the JSON response
    except Exception as e:
        st.error(f"Error contacting backend: {e}")       # If backend not running or error happens
    else:
        st.subheader("Analysis results")

        # Extract all the results sent back from backend
        suspicious = data.get("suspicious_ips", [])          # Brute-force IPs
        failed_counts = data.get("failed_counts", {})        # Fail count per IP
        failed_by_user = data.get("failed_by_user", {})      # Fail count per user
        suspicious_successes = data.get("suspicious_successes", [])  # Success after failures
        timeline = data.get("timeline", [])                  # Event timeline list


        # ===== 1. IPs with many failed logins =====
        st.markdown("### IPs with many failed logins")

        if suspicious:
            # Red warning banner at the top if brute-force detected
            st.markdown(
                """
                <div style="
                    background-color:#ff4d4d;
                    padding:15px;
                    border-radius:5px;
                    color:white;
                    font-weight:bold;
                    font-size:18px;
                    text-align:center;
                    margin-bottom:10px;
                ">
                    BRUTE-FORCE WARNING: Suspicious SSH activity detected
                </div>
                """,
                unsafe_allow_html=True
            )

            # Convert suspicious IPs into a table
            df_ips = pd.DataFrame({"IP address": suspicious})
            st.table(df_ips)
        else:
            st.success("No IP addresses reached the brute-force threshold in this log.")


        # ===== 2. Failed logins by IP address =====
        st.markdown("---")                       # Horizontal line
        st.markdown("### Failed logins by IP address")

        if failed_counts:
            # Table of how many failed logins each IP had
            df_counts = pd.DataFrame(
                failed_counts.items(),
                columns=["IP address", "Number of failed logins"]
            )
            st.table(df_counts)
        else:
            st.write("No failed SSH login attempts were found.")


        # ===== 3. Failed logins by username =====
        st.markdown("---")
        st.markdown("### Failed logins by username")

        if failed_by_user:
            df_users = pd.DataFrame(
                failed_by_user.items(),
                columns=["Username", "Number of failed logins"]
            )
            st.table(df_users)
        else:
            st.write("No failed logins linked to specific usernames were found.")


        # ===== 4. Suspicious successful logins =====
        st.markdown("---")
        st.markdown("### Successful logins after previous failures")

        if suspicious_successes:
            # Show successful logins that happened after failures (suspicious behaviour)
            df_success = pd.DataFrame(suspicious_successes)
            st.table(df_success)
        else:
            st.write("No successful logins were found after earlier failures from the same IP.")


        # ===== 5. Timeline =====
        st.markdown("---")
        st.markdown("### Timeline of matching log entries")

        st.write(
            "This shows each event with the extracted time, IP address, username, and the original log entry."
        )

        if timeline:
            rows = []                               # Prepare clean rows for table display

            for item in timeline:
                full_line = item.get("line", "")    # Full original log line

                # Extract the timestamp (first three fields: e.g. 'Nov 23 01:00:00')
                time_str = ""
                parts = full_line.split()
                if len(parts) >= 3:
                    time_str = " ".join(parts[0:3])

                # Add each event row
                rows.append({
                    "Time": time_str,               # Extracted timestamp
                    "IP address": item.get("ip", ""),   # IP of event
                    "Username": item.get("user", ""),    # Username involved
                    "Event type": item.get("type", ""),  # failed_login / successful_login
                    "Info": full_line,                  # Full log line
                })

            # Convert list  DataFrame  show table
            df_timeline = pd.DataFrame(rows)
            st.dataframe(df_timeline, use_container_width=True)

        else:
            st.write("No matching log entries were found in this file.")

else:
    # When no file is uploaded yet
    st.info("Use the sidebar to upload a log file and click **Analyze** to see results.")
