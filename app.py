from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DB_PATH = 'users.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        expires_at TEXT
    )''')
    conn.commit()
    conn.close()

@app.before_first_request
def setup():
    init_db()

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'admin' not in session:
        return redirect(url_for('login_admin'))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        expires = request.form['expires']
        hashed_pw = generate_password_hash(password)
        try:
            c.execute("INSERT INTO users (username, password, expires_at) VALUES (?, ?, ?)", 
                      (username, hashed_pw, expires))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Username already exists
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users)

@app.route('/admin/login', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        if request.form['username'] == 'admin' and request.form['password'] == 'adminpass':
            session['admin'] = True
            return redirect(url_for('admin'))
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password, expires_at FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        hashed_pw, expires_at = row
        if check_password_hash(hashed_pw, password):
            if expires_at >= datetime.utcnow().strftime("%Y-%m-%d"):
                return jsonify(success=True, message="Acceso autorizado")
            else:
                return jsonify(success=False, message="Usuario expirado")
    return jsonify(success=False, message="Credenciales inválidas")

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('login_admin'))

if __name__ == '__main__':
    app.run(debug=True)
