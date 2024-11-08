from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import sqlite3
import hashlib
import random
import string
import os
import uuid 

app = Flask(__name__) 
app.secret_key = 'a_random_insecure_secret_key'  # Still using a weak secret key
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Utility functions for database connection
def get_db_connection():
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize Database (with additional tables and vulnerabilities)
def init_db():
    conn = get_db_connection()
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

# User Registration - vulnerable to SQL Injection and Weak Password Storage
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"  # SQL Injection
        conn.execute(query)
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# Login - vulnerable to SQL Injection and Plaintext Password Storage
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"  # SQL Injection
        user = conn.execute(query).fetchone()
        if user:
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

# Dashboard - Broken Access Control (User can view any post if they change the URL)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    posts = conn.execute(f"SELECT * FROM posts WHERE user_id = {user_id}").fetchall()  # IDOR vulnerability
    return render_template('dashboard.html', posts=posts)

# View Post - XSS vulnerability (User-submitted content is not sanitized)
@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    conn = get_db_connection()
    post = conn.execute(f"SELECT * FROM posts WHERE id = {post_id}").fetchone()
    comments = conn.execute(f"SELECT * FROM comments WHERE post_id = {post_id}").fetchall()
    return render_template('view_post.html', post=post, comments=comments)

# Create Post - XSS vulnerability (Allowing unsanitized HTML and JS)
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

# File Upload - Insecure File Upload (Allowing dangerous file types like PHP, etc.)
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # No file type validation
        conn = get_db_connection()
        conn.execute("INSERT INTO files (user_id, filename) VALUES (?, ?)", (session['user_id'], filename))
        conn.commit()
        conn.close()
        return "File uploaded successfully"
    return render_template('upload.html')

# Session Fixation - Allowing attackers to steal session tokens
@app.route('/secure_dashboard')
def secure_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    posts = conn.execute(f"SELECT * FROM posts WHERE user_id = {user_id}").fetchall()
    return render_template('secure_dashboard.html', posts=posts)

# CSRF Vulnerability - Deleting posts without CSRF token protection
@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    conn.execute(f"DELETE FROM posts WHERE id = {post_id}")
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

# Remote Command Execution - Execute commands from user input (very dangerous!)
@app.route('/execute', methods=['GET', 'POST'])
def execute_command():
    if request.method == 'POST':
        command = request.form['command']
        output = os.popen(command).read()  # RCE Vulnerability: Executes arbitrary commands from user input
        return f"Command output: {output}"
    return render_template('execute.html')

# Improper Error Handling - Exposing sensitive data in error messages
@app.route('/error')
def trigger_error():
    try:
        1 / 0  # Deliberate ZeroDivisionError to demonstrate improper error handling
    except Exception as e:
        return str(e), 500  # This should be a generic message, not raw error

if __name__ == '__main__':
    init_db() 
    app.run(debug=True)
