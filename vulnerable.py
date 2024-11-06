from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
import sqlite3
import os
import hashlib
import random
import string
import uuid

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key'  # Weak secret key
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database connection
def get_db_connection():
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize Database
def init_db():
    conn = sqlite3.connect('vulnerable.db')
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT
    )''')
    conn.execute('''
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        title TEXT,
        content TEXT
    )''')
    conn.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        post_id INTEGER,
        user_id INTEGER,
        content TEXT
    )''')
    conn.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        filename TEXT
    )''')
    conn.execute('''
    CREATE TABLE IF NOT EXISTS session_tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER
    )''')
    conn.commit()
    conn.close()

# User Registration - vulnerable to SQL Injection
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
        conn.execute(query)  # SQL Injection vulnerability
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# Login - vulnerable to SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()  # SQL Injection vulnerability
        if user:
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

# Logout - simple session termination
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Dashboard - Broken Access Control (viewing posts without authorization check)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    posts = conn.execute(f"SELECT * FROM posts WHERE user_id = {user_id}").fetchall()  # IDOR vulnerability
    return render_template('dashboard.html', posts=posts)

# Create Post - vulnerable to XSS
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        user_id = session['user_id']
        conn = get_db_connection()
        conn.execute("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)", (user_id, title, content))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    return render_template('create_post.html')

# Comment on Post - XSS vulnerability
@app.route('/comment/<int:post_id>', methods=['GET', 'POST'])
def comment(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']
        user_id = session['user_id']
        conn = get_db_connection()
        conn.execute("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)", (post_id, user_id, content))
        conn.commit()
        conn.close()
        return redirect(url_for('view_post', post_id=post_id))
    return render_template('comment.html')

# View Post - XSS vulnerability
@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    conn = get_db_connection()
    post = conn.execute(f"SELECT * FROM posts WHERE id = {post_id}").fetchone()
    comments = conn.execute(f"SELECT * FROM comments WHERE post_id = {post_id}").fetchall()  # XSS vulnerability
    return render_template('view_post.html', post=post, comments=comments)

# Insecure File Upload - vulnerable to uploading malicious files
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # No file validation
        conn = get_db_connection()
        conn.execute("INSERT INTO files (user_id, filename) VALUES (?, ?)", (session['user_id'], filename))
        conn.commit()
        conn.close()
        return "File uploaded successfully"
    return render_template('upload.html')

# Session Fixation - Reusing a session token (vulnerable to attack)
@app.route('/secure_dashboard')
def secure_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    posts = conn.execute(f"SELECT * FROM posts WHERE user_id = {user_id}").fetchall()
    return render_template('secure_dashboard.html', posts=posts)

# CSRF Vulnerability - No CSRF token verification
@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    conn.execute(f"DELETE FROM posts WHERE id = {post_id}")
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
