from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")  # Explicit CORS for SocketIO
CORS(app)

USERS = {"user": "password"}  # Demo users
online_users = set()

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
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
    emit('users', list(online_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username and username in online_users:
        online_users.remove(username)
        emit('users', list(online_users), broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    from_user = data['from']
    to_user = data['to']
    message = data['message']
    time = datetime.now().strftime('%H:%M')
    emit('message', {'from': from_user, 'message': message, 'time': time}, room=request.sid)
    # Optionally, send to the recipient if you track their session

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)
