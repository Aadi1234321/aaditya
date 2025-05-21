import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from datetime import datetime
import os
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'
socketio = SocketIO(app, async_mode='threading')
CORS(app)

USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# Load users from file (initially empty or with demo user)
USERS = load_users()

online_users = set()
user_sessions = {}

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            error = "Please fill in both fields."
            return render_template('signup.html', error=error)

        if username in USERS:
            error = "Username already taken."
            return render_template('signup.html', error=error)

        USERS[username] = password
        save_users(USERS)
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        if USERS.get(username) == password:
            session['username'] = username
            return redirect(url_for('chat'))
        else:
            error = "Invalid credentials"
    return render_template('login.html', error=error)

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', username=session['username'])

@socketio.on('join')
def handle_join(username):
    online_users.add(username)
    user_sessions[username] = request.sid
    emit('users', list(online_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    username = None
    for user, session_id in user_sessions.items():
        if session_id == sid:
            username = user
            break
    if username:
        online_users.discard(username)
        user_sessions.pop(username)
        emit('users', list(online_users), broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    from_user = data['from']
    to_user = data['to']
    message = data['message']
    time = datetime.now().strftime('%H:%M')

    # Send message back to sender
    emit('message', {'from': from_user, 'message': message, 'time': time}, room=user_sessions[from_user])
    # Send message to recipient if online
    if to_user in user_sessions:
        emit('message', {'from': from_user, 'message': message, 'time': time}, room=user_sessions[to_user])

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)
