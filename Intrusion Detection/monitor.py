import asyncio
import os
import re
import datetime
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables
load_dotenv()

# Email configurations from .env
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
RECIPIENT_EMAIL = os.getenv("RECIPIENT_EMAIL")

# Suricata filtering configs
attacks = os.getenv("ATTACK_IDS", "").split(',')
ignore_list = os.getenv("IGNORED_ATTACK_IDS", "").split(',')
priorities = os.getenv("PRIORITY", "").split(',')

SNORT_LOG_FILE = r"C:\Snort\log\alert.ids"

# ---------------------- EMAIL SENDER FUNCTION ------------------------
def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = RECIPIENT_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
            print(f"✅ Email sent: {subject}")
    except Exception as e:
        print(f"❌ Error sending email: {e}")

# ---------------------- LOG PARSING FUNCTIONS ------------------------

def parse_snort_timestamp(log_line):
    """Extract timestamp from Snort log and fix year issue."""
    timestamp_match = re.search(r'(\d{2}/\d{2})-(\d{2}:\d{2}:\d{2}\.\d+)', log_line)
    
    if timestamp_match:
        month_day = timestamp_match.group(1) 
        time_part = timestamp_match.group(2)  
        
        # Use current year dynamically to avoid hardcoding
        current_year = datetime.datetime.now().year  
        full_timestamp = f"{current_year}/{month_day}-{time_part}"
        
        return datetime.datetime.strptime(full_timestamp, "%Y/%m/%d-%H:%M:%S.%f")
    
    return None  

def get_snort_priority(log_line):
    """Extract priority level from Snort log."""
    priority_match = re.search(r'\[Priority: (\d+)\]', log_line)
    return int(priority_match.group(1)) if priority_match else None

def get_snort_attack_id(log_line):
    """Extract attack ID (SID) from Snort log."""
    attack_id_match = re.search(r'\[1:(\d+):\d+\]', log_line)
    return attack_id_match.group(1) if attack_id_match else None


# ---------------------- MAIN LOG CHECK FUNCTION ------------------------

async def check_snort_log(filename, start_time):
    """Monitor Snort log file and send alerts for new attacks."""
    with open(filename, "r") as f:
        for line in f:
            event_timestamp = parse_snort_timestamp(line)
            priority_value = get_snort_priority(line)
            attack_id = get_snort_attack_id(line)

            if not event_timestamp or event_timestamp <= start_time:
                continue  
            if not attack_id:
                continue  
            # Check for priority-based alerts
            if str(priority_value) in priorities and attack_id not in ignore_list:
                subject = f"🚨 HIGH PRIORITY EVENT DETECTED (Priority {priority_value})"
                body = f"Snort Alert:\n\n{line.strip()}"
                print(f"Sending email: {subject}")
                send_email(subject, body)

            # Check for specific attack ID alerts
            elif attack_id in attacks and attack_id not in ignore_list:
                subject = f"🚨 ATTACK DETECTED - Attack ID: {attack_id}"
                body = f"Snort Alert:\n\n{line.strip()}"
                print(f"📩 Sending email: {subject}")
                send_email(subject, body)

    return datetime.datetime.now() 


# ---------------------- MAIN MONITOR FUNCTION ------------------------

async def main() -> None:
    start_time = datetime.datetime.now()
    print(f" Monitoring started at: {start_time}")

    # Send initial notification
    send_email("Alerting Enabled", "Snort alerting has been enabled and monitoring has started.")

    while True:
        start_time = await check_snort_log(SNORT_LOG_FILE, start_time)


# ---------------------- ENTRY POINT ------------------------

if __name__ == "__main__":
    asyncio.run(main())
