from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime, timezone
from collections import defaultdict
import json
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key'
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

USER_FILE = 'users.json'
CHAT_FILE = 'messages.json'

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

users = load_users()
message_history = load_messages()
unread_count = defaultdict(lambda: defaultdict(int))
typing_users = defaultdict(set)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    global users
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if username in users:
            error = "Username already exists."
        else:
            users[username] = {
                'password_hash': bcrypt.generate_password_hash(password).decode('utf-8'),
                'nickname': username,
                'avatar_url': None,
                'last_seen': None,
                'online': False
            }
            save_users()
            return redirect(url_for('login'))
    return render_template('signup.html', error=error)

@app.route('/', methods=['GET', 'POST'])
def login():
    global users
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        user = users.get(username)

        if not user or not bcrypt.check_password_hash(user['password_hash'], password):
            error = "Invalid username or password."
        else:
            session['username'] = username
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
            "nickname": data['nickname'],
            "avatar_url": data['avatar_url'],
            "online": data['online'],
            "last_seen": last_seen_str(data['last_seen']) if data['last_seen'] else "never",
            "unread": unread_count[for_user][u]
        }
        for u, data in users.items() # Removed the if u != for_user condition
    ]

if __name__ == '__main__':
    socketio.run(app, debug=True)
