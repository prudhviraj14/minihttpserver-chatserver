# email_service.py
import smtplib, ssl, json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

CFG_PATH = Path("config.json")
if not CFG_PATH.exists():
    raise RuntimeError("config.json missing. Create it with your email and app password.")

with open(CFG_PATH, "r") as f:
    CFG = json.load(f)

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER = CFG.get("email")
SENDER_PASS = CFG.get("email_password")

def send_reset_code(recipient_email, username, reset_code):
    subject = "Password Reset Code - Mini Messaging Platform"
    body = f"""Hello {username},

You requested a password reset.

Your reset code is: {reset_code}

If you didn't request this, ignore this email.

Regards,
Mini Messaging Platform
"""
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER
        msg["To"] = recipient_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SENDER, SENDER_PASS)
            server.send_message(msg)
        print(f"✅ Sent reset code to {recipient_email}")
        return True
    except Exception as e:
        print("❌ Email send error:", e)
        return False
