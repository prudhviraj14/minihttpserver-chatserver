import os
from datetime import timedelta

# Configuration
HOST = '0.0.0.0' if os.getenv('RENDER') else '127.0.0.1'
PORT = int(os.getenv('PORT', 8080))
UPLOAD_DIR = 'uploads'
USERS_DB = 'users.json'
MESSAGES_DB = 'messages.json'
FEEDBACK_DB = 'feedback.json'
ADMIN_DB = 'admin_users.json'
RESET_CODES_DB = 'reset_codes.json'

# Email Configuration (Update with your SMTP details)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "your-email@gmail.com"  # Update this
EMAIL_PASSWORD = "your-app-password"    # Update this

# Security
SESSION_TIMEOUT = timedelta(hours=24)
RESET_CODE_EXPIRY = timedelta(minutes=15)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# Admin Configuration
ADMIN_USERNAME = "admin"
ADMIN_EMAIL = "admin@messaging.com"