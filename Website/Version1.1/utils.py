import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from zxcvbn import zxcvbn
from dotenv import load_dotenv
import re

load_dotenv()

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

def load_wordlist(file_path):
    """Load a wordlist from file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return set(line.strip().lower() for line in f)
    except FileNotFoundError:
        print(f"Warning: Wordlist file {file_path} not found")
        return set()

def check_password_strength(password):
    """Check password strength using multiple criteria."""
    # Basic requirements
    checks = {
        'length': len(password) >= 8,
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'numbers': bool(re.search(r'[0-9]', password)),
        'special': bool(re.search(r'[^A-Za-z0-9]', password))
    }
    
    # Count passed checks
    passed_checks = sum(checks.values())
    total_checks = len(checks)
    strength_percentage = (passed_checks / total_checks) * 100
    
    # Use zxcvbn for additional analysis
    zxcvbn_result = zxcvbn(password)
    zxcvbn_score = zxcvbn_result['score']  # 0-4 score
    
    # Combine our basic checks with zxcvbn score
    if strength_percentage <= 20:
        return False, "Very weak password. Please follow the password requirements."
    elif strength_percentage <= 40:
        return False, "Weak password. Please include more character types."
    elif strength_percentage <= 60:
        return False, "Medium strength password. Consider making it stronger."
    elif strength_percentage <= 80:
        return True, "Strong password!"
    else:
        return True, "Very strong password!"

def send_email(to_email, subject, body):
    """Send an email using SMTP."""
    if not all([EMAIL_USER, EMAIL_PASSWORD]):
        print("Warning: Email credentials not configured")
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS 