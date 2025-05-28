from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime, timezone
from collections import defaultdict
import json
import os
import re
import random
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'your-secret-key'
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

USER_FILE = 'users.json'
CHAT_FILE = 'messages.json'
STATUS_FILE = 'status.json'

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'avatars')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

MEDIA_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'media')
os.makedirs(MEDIA_FOLDER, exist_ok=True)
app.config['MEDIA_FOLDER'] = MEDIA_FOLDER

otp_store = {}  # {email: {"otp": ..., "timestamp": ...}}

def load_users():
    if os.path.exists(USER_FILE):
        try:
            with open(USER_FILE, 'r') as f:
                raw_users = json.load(f)
                for user in raw_users.values():
                    if user['last_seen']:
                        user['last_seen'] = datetime.fromisoformat(user['last_seen'])
                return raw_users
        except (json.JSONDecodeError, ValueError):
            print("Error: users.json is invalid. Replacing with empty user list.")
            return {}
    else:
        with open(USER_FILE, 'w') as f:
            json.dump({}, f)
    return {}

def save_users():
    global users
    serializable_users = {
        username: {
            **user,
            'last_seen': user['last_seen'].isoformat() if user['last_seen'] else None
        }
        for username, user in users.items()
    }
    with open(USER_FILE, 'w') as f:
        json.dump(serializable_users, f)

def load_messages():
    if os.path.exists(CHAT_FILE):
        try:
            with open(CHAT_FILE, 'r') as f:
                data = json.load(f)
                return defaultdict(list, {tuple(k.split('|')): v for k, v in data.items()})
        except (json.JSONDecodeError, ValueError):
            print("Error: messages.json is invalid. Replacing with empty message history.")
            return defaultdict(list)
    else:
        with open(CHAT_FILE, 'w') as f:
            json.dump({}, f)
    return defaultdict(list)

def save_messages():
    global message_history
    with open(CHAT_FILE, 'w') as f:
        json.dump({"|".join(k): v for k, v in message_history.items()}, f)

def load_status():
    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError):
            print("Error: status.json is invalid. Replacing with empty status.")
            return {}
    else:
        with open(STATUS_FILE, 'w') as f:
            json.dump({}, f)
    return {}

def save_status():
    global user_status
    with open(STATUS_FILE, 'w') as f:
        json.dump(user_status, f)

users = load_users()
message_history = load_messages()
user_status = load_status()
unread_count = defaultdict(lambda: defaultdict(int))
typing_users = defaultdict(set)

@app.route('/profile')
def profile():
    username = session.get('username')
    if not username or username not in users:
        return jsonify({}), 401
    user = users[username]
    return jsonify({
        "username": username,
        "email": user.get("email"),
        "name": user.get("name"),
        "nickname": user.get("nickname"),
        "avatar_url": user.get("avatar_url"),
        "mobile": user.get("mobile"),
        "last_seen": user.get("last_seen").isoformat() if user.get("last_seen") else None,
        "online": user.get("online"),
    })

@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    username = session.get('username')
    if not username or username not in users:
        return jsonify({"error": "Not logged in"}), 401
    file = request.files.get('avatar')
    if not file:
        return jsonify({"error": "No file"}), 400
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ('.jpg', '.jpeg', '.png', '.gif', '.webp'):
        return jsonify({"error": "Invalid file type"}), 400
    filename = f"{username}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    avatar_url = url_for('avatar_file', filename=filename)
    users[username]['avatar_url'] = avatar_url
    save_users()
    return jsonify({"avatar_url": avatar_url})

@app.route('/static/avatars/<filename>')
def avatar_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def is_valid_email(email):
    # Simple regex for email validation
    return re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email) is not None

def send_otp_email(email, otp):
    # Make sure to use your real SMTP credentials and allow less secure apps if using Gmail.
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USER = "aadityanokhwal5@gmail.com"  # <-- Replace with your email
    SMTP_PASS = "xuuz hrur dgan hkes"      # <-- Replace with your app password (not your normal password!)

    msg = MIMEText(f"Your OTP for Chat-by-Aaditya signup is: {otp}")
    msg["Subject"] = "Your OTP for Chat-by-Aaditya"
    msg["From"] = SMTP_USER
    msg["To"] = email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [email], msg.as_string())
        return True
    except Exception as e:
        print("Email send error:", e)
        return False

@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form.get('email', '').strip()
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email"}), 400
    otp = str(random.randint(100000, 999999))
    otp_store[email] = {"otp": otp, "timestamp": datetime.now(timezone.utc).timestamp()}
    if send_otp_email(email, otp):
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Failed to send OTP"}), 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    global users
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        nickname = request.form.get('nickname', '').strip()
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip()
        mobile = request.form.get('mobile', '').strip()
        otp = request.form.get('otp', '').strip()
        if username in users:
            error = "Username already exists."
        elif email and not is_valid_email(email):
            error = "Invalid email address."
        elif email not in otp_store or otp_store[email]["otp"] != otp:
            error = "Invalid or expired OTP."
        else:
            users[username] = {
                'password_hash': bcrypt.generate_password_hash(password).decode('utf-8'),
                'nickname': nickname or username,
                'email': email,
                'name': name,
                'mobile': mobile,
                'avatar_url': None,
                'last_seen': None,
                'online': False
            }
            save_users()
            otp_store.pop(email, None)
            return redirect(url_for('login'))
    return render_template('signup.html', error=error)

@app.route('/', methods=['GET', 'POST'])
def login():
    global users
    error = None
    if request.method == 'POST':
        login_id = request.form['username'].strip()
        password = request.form['password'].strip()
        user = None

        # Try to find user by username, email, or mobile
        for u in users.values():
            if (
                u.get('email', '').lower() == login_id.lower()
                or u.get('mobile', '').lower() == login_id.lower()
                or u.get('nickname', '').lower() == login_id.lower()
            ):
                user = u
                break
        if not user and login_id in users:
            user = users[login_id]

        if not user or not bcrypt.check_password_hash(user['password_hash'], password):
            error = "Invalid username/email/mobile or password."
        else:
            # Find the username key for this user
            username_key = None
            for uname, u in users.items():
                if u is user:
                    username_key = uname
                    break
            session['username'] = username_key
            user['online'] = True
            user['last_seen'] = datetime.now(timezone.utc)
            save_users()
            return redirect(url_for('chat'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    global users
    username = session.get('username')
    if username and username in users:
        users[username]['online'] = False
        users[username]['last_seen'] = datetime.now(timezone.utc)
        save_users()
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    username = session.get('username')
    if not username or username not in users:
        return redirect(url_for('login'))
    return render_template('chat.html', username=username)

@socketio.on('join')
def on_join(username):
    global users
    if username in users:
        users[username]['online'] = True
        users[username]['last_seen'] = datetime.now(timezone.utc)
        save_users()
    join_room(username)
    # Broadcast the full user list to all clients
    emit('users', serialize_users(username), broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    global users
    username = session.get('username')
    if username and username in users:
        users[username]['online'] = False
        users[username]['last_seen'] = datetime.now(timezone.utc)
        save_users()
        # Broadcast the full user list to all clients
        emit('users', serialize_users(username), broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    global message_history, unread_count
    from_user = data['from']
    to_user = data['to']
    message = data['message']
    timestamp = datetime.now(timezone.utc).strftime("%H:%M")

    key = tuple(sorted([from_user, to_user]))
    # Mark message as unread for the recipient
    message_history[key].append({'from': from_user, 'message': message, 'time': timestamp, 'read': False})
    save_messages()

    emit('private_message', {'from': from_user, 'message': message, 'time': timestamp, 'read': False}, room=to_user)
    emit('private_message', {'from': from_user, 'message': message, 'time': timestamp, 'read': True}, room=from_user)

    if to_user != from_user:
        unread_count[to_user][from_user] += 1   

@socketio.on('get_history')
def send_history(data):
    global message_history, unread_count
    user1 = data['from']
    user2 = data['to']
    key = tuple(sorted([user1, user2]))
    # Mark all messages from user2 to user1 as read
    for msg in message_history[key]:
        if msg['from'] == user2:
            msg['read'] = True
    save_messages()
    history = message_history[key]
    emit('chat_history', history)
    unread_count[user1][user2] = 0

@socketio.on('typing')
def handle_typing(data):
    from_user = data['from']
    to_user = data['to']
    emit('typing', {'from': from_user}, room=to_user)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    from_user = data['from']
    to_user = data['to']
    emit('stop_typing', {'from': from_user}, room=to_user)

@socketio.on('delete_messages')
def delete_messages(data):
    """
    data = {
        'from': <username>,
        'to': <username>,
        'timestamps': [<timestamp1>, <timestamp2>, ...]
    }
    """
    global message_history
    user1 = data['from']
    user2 = data['to']
    timestamps = set(data.get('timestamps', []))
    key = tuple(sorted([user1, user2]))
    # Allow deleting any message matching the given timestamps (selected messages)
    message_history[key] = [
        msg for msg in message_history[key]
        if msg['time'] not in timestamps
    ]
    save_messages()
    # Notify both users to update their chat history
    emit('chat_history', message_history[key], room=user1)
    emit('chat_history', message_history[key], room=user2)

# Add a mapping for user-specific display names (nicknames for others)
user_display_names = defaultdict(dict)  # {viewer_username: {other_username: custom_name}}

@app.route('/set_display_name', methods=['POST'])
def set_display_name():
    if 'username' not in session:
        return jsonify({"error": "Not logged in"}), 401
    viewer = session['username']
    data = request.get_json()
    target = data.get('target')
    display_name = data.get('display_name', '').strip()
    if not target or target == viewer or target not in users:
        return jsonify({"error": "Invalid target"}), 400
    if display_name:
        user_display_names[viewer][target] = display_name
    else:
        user_display_names[viewer].pop(target, None)
    return jsonify({"success": True})

@app.route('/upload_media', methods=['POST'])
def upload_media():
    username = session.get('username')
    if not username or username not in users:
        return jsonify({"error": "Not logged in"}), 401
    file = request.files.get('media')
    if not file:
        return jsonify({"error": "No file"}), 400
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.mp4', '.mp3', '.wav', '.ogg', '.pdf', '.doc', '.docx'):
        return jsonify({"error": "Invalid file type"}), 400
    filename = f"{username}_{int(datetime.now().timestamp())}{ext}"
    filepath = os.path.join(app.config['MEDIA_FOLDER'], filename)
    file.save(filepath)
    media_url = url_for('media_file', filename=filename)
    return jsonify({"media_url": media_url})

@app.route('/static/media/<filename>')
def media_file(filename):
    return send_from_directory(app.config['MEDIA_FOLDER'], filename)

@socketio.on('media_message')
def handle_media_message(data):
    """
    data = {
        'from': <username>,
        'to': <username>,
        'media_url': <url>,
        'media_type': <type>,  # e.g. 'image', 'video', 'audio', 'file'
        'caption': <optional>
    }
    """
    global message_history, unread_count
    from_user = data['from']
    to_user = data['to']
    media_url = data['media_url']
    media_type = data.get('media_type', 'file')
    caption = data.get('caption', '')
    timestamp = datetime.now(timezone.utc).strftime("%H:%M")

    key = tuple(sorted([from_user, to_user]))
    message_history[key].append({
        'from': from_user,
        'media_url': media_url,
        'media_type': media_type,
        'caption': caption,
        'time': timestamp,
        'read': False
    })
    save_messages()

    emit('media_message', {
        'from': from_user,
        'media_url': media_url,
        'media_type': media_type,
        'caption': caption,
        'time': timestamp,
        'read': False
    }, room=to_user)
    emit('media_message', {
        'from': from_user,
        'media_url': media_url,
        'media_type': media_type,
        'caption': caption,
        'time': timestamp,
        'read': True
    }, room=from_user)

    if to_user != from_user:
        unread_count[to_user][from_user] += 1

@app.route('/upload_status', methods=['POST'])
def upload_status():
    username = session.get('username')
    if not username or username not in users:
        return jsonify({"error": "Not logged in"}), 401
    # Accept both file and text, but at least one must be present
    file = request.files.get('status_media')
    text = request.form.get('status_text', '').strip()
    if not file and not text:
        return jsonify({"error": "Status text or media required"}), 400
    status_url = None
    media_type = None
    if file:
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.mp4'):
            return jsonify({"error": "Invalid file type"}), 400
        filename = f"{username}_status_{int(datetime.now().timestamp())}{ext}"
        filepath = os.path.join(app.config['MEDIA_FOLDER'], filename)
        file.save(filepath)
        status_url = url_for('media_file', filename=filename)
        if ext in ('.jpg', '.jpeg', '.png', '.gif', '.webp'):
            media_type = 'image'
        elif ext == '.mp4':
            media_type = 'video'
    user_status[username] = {
        "status_url": status_url,
        "status_text": text,
        "media_type": media_type,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    save_status()
    return jsonify({"success": True})

@app.route('/get_status/<username>')
def get_status(username):
    # Allow any logged-in user to view any user's status
    if 'username' not in session or username not in users:
        return jsonify({"error": "Not found"}), 404
    status = user_status.get(username)
    if not status:
        return jsonify({"error": "No status"}), 404
    user = users.get(username)
    return jsonify({
        "username": username,
        "status_url": status.get("status_url"),
        "status_text": status.get("status_text"),
        "media_type": status.get("media_type"),
        "timestamp": status.get("timestamp"),
        "avatar_url": user.get("avatar_url") if user else None,
        "nickname": user.get("nickname") if user else username
    })

@app.route('/get_statuses')
def get_statuses():
    # Return all statuses for all users (for status list in sidebar)
    result = []
    for username, status in user_status.items():
        user = users.get(username)
        result.append({
            "username": username,
            "nickname": user.get("nickname") if user else username,
            "avatar_url": user.get("avatar_url") if user else None,
            "status_url": status.get("status_url"),
            "media_type": status.get("media_type"),
            "timestamp": status.get("timestamp"),
        })
    # Sort by most recent
    result.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
    return jsonify(result)

def serialize_users(for_user):
    def last_seen_str(dt):
        if not dt:
            return "never"
        delta = datetime.now(timezone.utc) - dt
        if delta.total_seconds() < 60:
            return "just now"
        elif delta.total_seconds() < 3600:
            return f"{int(delta.total_seconds() // 60)} minutes ago"
        elif delta.total_seconds() < 86400:
            return f"{int(delta.total_seconds() // 3600)} hours ago"
        else:
            return dt.strftime("%Y-%m-%d")

    return [
        {
            "username": u,
            # Use custom display name if set by for_user, else fallback to user's nickname or username
            "nickname": user_display_names.get(for_user, {}).get(u) or data.get('nickname') or u,
            "avatar_url": data.get('avatar_url'),
            "online": data.get('online'),
            "last_seen": last_seen_str(data.get('last_seen')) if data.get('last_seen') else "never",
            "unread": unread_count[for_user][u]
        }
        for u, data in users.items()
    ]

@app.route('/status', methods=['GET', 'POST'])
def status_page():
    username = session.get('username')
    if not username or username not in users:
        return redirect(url_for('login'))
    # WhatsApp-like: show user's own status at top, then recent updates
    if request.method == 'POST':
        file = request.files.get('status_media')
        text = request.form.get('status_text', '').strip()
        if not file and not text:
            return render_template('status.html', username=username, error="Status text or media required")
        status_url = None
        media_type = None
        if file:
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.mp4'):
                return render_template('status.html', username=username, error="Invalid file type")
            filename = f"{username}_status_{int(datetime.now().timestamp())}{ext}"
            filepath = os.path.join(app.config['MEDIA_FOLDER'], filename)
            file.save(filepath)
            status_url = url_for('media_file', filename=filename)
            if ext in ('.jpg', '.jpeg', '.png', '.gif', '.webp'):
                media_type = 'image'
            elif ext == '.mp4':
                media_type = 'video'
        user_status[username] = {
            "status_url": status_url,
            "status_text": text,
            "media_type": media_type,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        save_status()
        return redirect(url_for('status_page'))
    # GET: show all statuses, WhatsApp style
    all_statuses = []
    my_status = None
    for uname, status in user_status.items():
        user = users.get(uname)
        s = {
            "username": uname,
            "nickname": user.get("nickname") if user else uname,
            "avatar_url": user.get("avatar_url") if user else None,
            "status_url": status.get("status_url"),
            "status_text": status.get("status_text"),
            "media_type": status.get("media_type"),
            "timestamp": status.get("timestamp"),
        }
        if uname == username:
            my_status = s
        else:
            all_statuses.append(s)
    all_statuses.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
    return render_template('status.html', username=username, my_status=my_status, statuses=all_statuses, error=None)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    success = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        otp = request.form.get('otp', '').strip()
        new_password = request.form.get('new_password', '').strip()
        # Step 1: Request OTP
        if 'send_otp' in request.form:
            user = users.get(username)
            if not user or user.get('email') != email:
                error = "Username and email do not match."
            else:
                otp_code = str(random.randint(100000, 999999))
                otp_store[email] = {"otp": otp_code, "timestamp": datetime.now(timezone.utc).timestamp()}
                if send_otp_email(email, otp_code):
                    success = "OTP sent to your email."
                else:
                    error = "Failed to send OTP."
        # Step 2: Reset password
        elif 'reset_password' in request.form:
            user = users.get(username)
            if not user or user.get('email') != email:
                error = "Username and email do not match."
            elif email not in otp_store or otp_store[email]["otp"] != otp:
                error = "Invalid or expired OTP."
            elif not new_password or len(new_password) < 4:
                error = "Password too short."
            else:
                user['password_hash'] = bcrypt.generate_password_hash(new_password).decode('utf-8')
                save_users()
                otp_store.pop(email, None)
                success = "Password reset successful. You can now log in."
    return render_template('forgot_password.html', error=error, success=success)

# WhatsApp-like features are implemented in the frontend (HTML/CSS/JS).
# Backend logic for chat, users, avatars, media, and display names is already present.
# For a more WhatsApp-like experience, focus on the HTML/CSS/JS in templates/chat.html.

if __name__ == '__main__':
    socketio.run(app, debug=True)
