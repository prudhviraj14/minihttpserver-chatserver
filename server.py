# server.py
from http.server import SimpleHTTPRequestHandler, HTTPServer
import urllib.parse, os, json, base64, cgi, threading, uuid
from pathlib import Path
import random
from database import (
    setup_database, add_user, verify_user, get_user, set_reset_code, verify_reset_code,
    update_password, list_users, add_message, get_messages_for_pair, get_messages_for_user,
    add_feedback, get_all_feedback, get_all_messages
)
from email_service import send_reset_code
from zoneinfo import ZoneInfo
from datetime import datetime

# Load config
CFG_PATH = Path("config.json")
if not CFG_PATH.exists():
    raise RuntimeError("config.json missing. Create it with your email and app password.")

with open(CFG_PATH, "r") as f:
    CFG = json.load(f)

UPLOAD_DIR = CFG.get("upload_dir", "static/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
PORT = int(CFG.get("server_port", 8080))
ZONE = ZoneInfo("Asia/Kolkata")

# Ensure DB + default admin
setup_database()

# Simple in-memory session store (token -> username)
SESSIONS = {}

def generate_session():
    return str(uuid.uuid4())

def now_ist():
    return datetime.now(ZONE).isoformat(timespec='seconds')

class Handler(SimpleHTTPRequestHandler):
    # Serve templates from templates/ by path / or /templates/<file>
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Admin data fetch endpoint (GET)
        if path == "/admin-data":
            # requires admin session cookie
            self.handle_admin_data(parsed.query)
            return

        # download file: /download?file=<filename>
        if path == "/download":
            qs = urllib.parse.parse_qs(parsed.query)
            fname = qs.get("file", [""])[0]
            return self.handle_file_download(fname)

        # Serve static files or templates
        if path == "/" or path == "/index.html":
            return self.serve_template("index.html")
        if path.startswith("/templates/"):
            fn = path.replace("/templates/", "", 1)
            return self.serve_template(fn)
        if path.startswith("/static/"):
            return super().do_GET()  # default static handler

        # Unknown GET
        return self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Parse body: support form-url-encoded (default) and multipart/form-data
        content_type = self.headers.get('Content-Type', '')
        data = {}
        if content_type.startswith("multipart/form-data"):
            ctype, pdict = cgi.parse_header(content_type)
            pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
            pdict['CONTENT-LENGTH'] = int(self.headers.get('Content-Length', 0))
            fields = cgi.parse_multipart(self.rfile, pdict)
            # fields values are lists
            for k, v in fields.items():
                data[k] = v[0]
        else:
            length = int(self.headers.get('Content-Length', 0) or 0)
            body = self.rfile.read(length).decode('utf-8', errors='ignore')
            params = urllib.parse.parse_qs(body)
            for k, v in params.items():
                data[k] = v[0]

        if path == "/register":
            return self.handle_register(data)
        if path == "/login":
            return self.handle_login(data)
        if path == "/logout":
            return self.handle_logout()
        if path == "/contacts":
            return self.handle_contacts()
        if path == "/get-messages":
            return self.handle_get_messages(data)
        if path == "/send-message":
            return self.handle_send_message(data)
        if path == "/upload-file":
            return self.handle_upload_file(data)
        if path == "/forgot-password":
            return self.handle_forgot(data)
        if path == "/verify-code":
            return self.handle_verify(data)
        if path == "/reset-password":
            return self.handle_reset(data)
        if path == "/feedback":
            return self.handle_feedback(data)

        return self.json_response({"success": False, "message": "Unknown endpoint"})

    # ---------- helpers ----------
    def serve_template(self, filename):
        tpl_path = Path("templates") / filename
        if not tpl_path.exists():
            return self.send_error(404, "Template not found")
        try:
            with open(tpl_path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            print("serve_template error:", e)
            self.send_error(500, "Internal server error")

    def json_response(self, obj, status=200, extra_headers=None):
        payload = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def get_session_user(self):
        cookie = self.headers.get("Cookie", "")
        if "session=" in cookie:
            token = cookie.split("session=")[1].split(";")[0]
            return SESSIONS.get(token)
        return None

    # ---------- route handlers ----------
    def handle_register(self, data):
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        email = (data.get("email") or "").strip() or None
        if not username or not password:
            return self.json_response({"success": False, "message": "username & password required"})
        if get_user(username):
            return self.json_response({"success": False, "message": "username already exists"})
        try:
            add_user(username, password, email)
            print(f"[{now_ist()}] Registered: {username}")
            return self.json_response({"success": True, "message": "registered"})
        except Exception as e:
            print("register error:", e)
            return self.json_response({"success": False, "message": "registration failed"})

    def handle_login(self, data):
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if verify_user(username, password):
            token = generate_session()
            SESSIONS[token] = username
            print(f"[{now_ist()}] Login: {username}")
            # set cookie
            headers = {"Set-Cookie": f"session={token}; Path=/; HttpOnly"}
            return self.json_response({"success": True, "message": "login"}, extra_headers=headers)
        else:
            return self.json_response({"success": False, "message": "invalid credentials"})

    def handle_logout(self):
        cookie = self.headers.get("Cookie", "")
        if "session=" in cookie:
            token = cookie.split("session=")[1].split(";")[0]
            SESSIONS.pop(token, None)
        # clear cookie
        self.send_response(200)
        self.send_header("Set-Cookie", "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
        self.end_headers()
        self.wfile.write(b"Logged out")

    def handle_contacts(self):
        user = self.get_session_user()
        if not user:
            return self.json_response({"success": False, "message": "not authenticated"}, status=401)
        users = list_users()
        # filter out current user from contacts
        contacts = [u for u in users if u["username"] != user]
        return self.json_response({"success": True, "contacts": contacts})

    def handle_get_messages(self, data):
        user = self.get_session_user()
        if not user:
            return self.json_response({"success": False, "message": "not authenticated"}, status=401)
        other = (data.get("other") or "").strip()
        if not other:
            return self.json_response({"success": False, "message": "other user required"})
        msgs = get_messages_for_pair(user, other)
        return self.json_response({"success": True, "messages": msgs})

    def handle_send_message(self, data):
        user = self.get_session_user()
        if not user:
            return self.json_response({"success": False, "message": "not authenticated"}, status=401)
        other = (data.get("to") or "").strip()
        text = data.get("message") or ""
        if not other:
            return self.json_response({"success": False, "message": "recipient required"})
        if not get_user(other):
            return self.json_response({"success": False, "message": "recipient does not exist"})
        add_message(user, other, text, None)
        print(f"[{now_ist()}] {user} -> {other} (msg)")
        return self.json_response({"success": True})

    def handle_upload_file(self, data):
        # supports two approaches:
        # 1) client sends 'filename' and 'filedata' (base64 string)
        # 2) multipart/form-data with file field 'file'
        user = self.get_session_user()
        if not user:
            return self.json_response({"success": False, "message": "not authenticated"}, status=401)

        # prefer multipart if present
        if isinstance(data.get("file"), (bytes, bytearray)):
            # raw file bytes obtained from cgi.parse_multipart
            filename = data.get("filename") or "upload.bin"
            file_bytes = data.get("file")
        elif data.get("filedata"):
            filename = data.get("filename") or "upload.bin"
            try:
                file_bytes = base64.b64decode(data.get("filedata"))
            except Exception as e:
                return self.json_response({"success": False, "message": "invalid file data"})
        else:
            return self.json_response({"success": False, "message": "no file provided"})

        to_user = (data.get("to") or "").strip()
        if not to_user:
            return self.json_response({"success": False, "message": "recipient required"})
        if not get_user(to_user):
            return self.json_response({"success": False, "message": "recipient not found"})

        safe_name = f"{user}_{int(datetime.now().timestamp())}_{os.path.basename(filename)}"
        path = os.path.join(UPLOAD_DIR, safe_name)
        with open(path, "wb") as f:
            f.write(file_bytes)
        add_message(user, to_user, f"Sent a file: {filename}", safe_name)
        print(f"[{now_ist()}] {user} -> {to_user} (file: {safe_name})")
        return self.json_response({"success": True, "file": safe_name})

    def handle_file_download(self, fname):
        user = self.get_session_user()
        if not user:
            return self.send_error(401, "Unauthorized")
        if not fname:
            return self.send_error(400, "file param required")
        safe = os.path.basename(fname)
        full = os.path.join(UPLOAD_DIR, safe)
        if not os.path.exists(full):
            return self.send_error(404, "File not found")
        # verify that file belongs to a message where user is sender or receiver
        msgs = get_all_messages()
        allowed = False
        for m in msgs:
            if m.get("file_path") == safe and (m.get("sender") == user or m.get("receiver") == user):
                allowed = True
                break
        if not allowed:
            return self.send_error(403, "Forbidden")
        try:
            with open(full, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{safe.split("_",2)[-1]}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            print("download error:", e)
            self.send_error(500, "Internal error")

    def handle_forgot(self, data):
        username = (data.get("username") or "").strip()
        user = get_user(username)
        if not user:
            return self.json_response({"success": False, "message": "user not found"})
        if not user.get("email"):
            return self.json_response({"success": False, "message": "no email registered"})
        code = str(random.randint(100000, 999999))
        set_reset_code(username, code)
        # send email async
        threading.Thread(target=send_reset_code, args=(user["email"], username, code), daemon=True).start()
        print(f"[{now_ist()}] Sent reset code to {username}")
        return self.json_response({"success": True})

    def handle_verify(self, data):
        username = (data.get("username") or "").strip()
        code = (data.get("code") or "").strip()
        ok = verify_reset_code(username, code)
        return self.json_response({"success": ok, "message": "verified" if ok else "invalid or expired code"})

    def handle_reset(self, data):
        username = (data.get("username") or "").strip()
        newpw = data.get("new_password") or ""
        confirm = data.get("confirm_password") or ""
        if newpw != confirm:
            return self.json_response({"success": False, "message": "passwords do not match"})
        update_password(username, newpw)
        print(f"[{now_ist()}] Password updated for {username}")
        return self.json_response({"success": True})

    def handle_feedback(self, data):
        user = self.get_session_user()
        if not user:
            return self.json_response({"success": False, "message": "not authenticated"}, status=401)
        fb_type = data.get("type") or "general"
        msg = data.get("message") or ""
        add_feedback(user, fb_type, msg)
        print(f"[{now_ist()}] Feedback from {user}")
        return self.json_response({"success": True})

    def handle_admin_data(self, query):
        user = self.get_session_user()
        if not user:
            return self.json_response({"success": False, "message": "not authenticated"}, status=401)
        u = get_user(user)
        if not u or not u.get("is_admin"):
            return self.json_response({"success": False, "message": "forbidden"}, status=403)
        # return users, messages, feedback
        us = list_users()
        msgs = get_all_messages()
        fbs = get_all_feedback()
        return self.json_response({"success": True, "users": us, "messages": msgs, "feedback": fbs})

def run():
    print("Starting server on port", PORT)
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down")
        server.server_close()

if __name__ == "__main__":
    run()
