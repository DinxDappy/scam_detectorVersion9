from flask import Flask, render_template_string, request, redirect, session, url_for, flash, render_template, send_file
import json
import re
import os
import hashlib
import random
from datetime import datetime
import requests

app = Flask(__name__)
app.secret_key = 'your-secret-key'

DATA_FILE = 'scam_data.json'
USERS_FILE = 'users.json'
ANALYTICS_FILE = 'analytics.json'
TELEGRAM_TOKEN = 'your-telegram-bot-token-here'
ADS_FILE = 'ads.json'

# Load and save functions
def load_json(file, default):
    if os.path.exists(file):
        with open(file, 'r') as f:
            return json.load(f)
    return default

def save_json(file, data):  # removed stray render_template
    with open(file, 'w') as f:
        json.dump(data, f, indent=4)

# User and scam data
load_scam_data = lambda: load_json(DATA_FILE, {"scam_keywords": [], "suspicious_links": [], "fake_numbers": []})
save_scam_data = lambda data: save_json(DATA_FILE, data)

load_users = lambda: load_json(USERS_FILE, {})
save_users = lambda users: save_json(USERS_FILE, users)

load_analytics = lambda: load_json(ANALYTICS_FILE, {"total_scans": 0, "scams_detected": 0, "last_scan": ""})
save_analytics = lambda data: save_json(ANALYTICS_FILE, data)

def load_ads():
    return load_json(ADS_FILE, [
        {"img": "ads/ad1.jpg", "link": "https://example.com/product1"},
        {"img": "ads/ad2.jpg", "link": "https://example.com/product2"},
        {"img": "ads/ad3.jpg", "link": "https://example.com/product3"}
    ])

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_admin():
    return session.get('user') == 'admin'

def is_scam_message(message, data):
    lower_msg = message.lower()
    for keyword in data['scam_keywords']:
        if keyword.lower() in lower_msg:
            return True, f"Suspicious keyword found: '{keyword}'"
    for link in data['suspicious_links']:
        if link.lower() in lower_msg:
            return True, f"Suspicious link found: '{link}'"
    for number in data['fake_numbers']:
        if number in message:
            return True, f"Suspicious number found: '{number}'"
    if re.search(r"https?://(bit\\.ly|tinyurl\\.com|shorturl\\.at|is\\.gd)/", message):
        return True, "Message contains a shortened URL."
    return False, "Message appears safe."

# Telegram Webhook
@app.route('/webhook', methods=['POST'])
def telegram_webhook():
    scam_data = load_scam_data()
    data = request.get_json()
    if 'message' in data and 'text' in data['message']:
        chat_id = data['message']['chat']['id']
        msg_text = data['message']['text']
        is_scam, response = is_scam_message(msg_text, scam_data)
        reply = f"⚠️ Scam Alert: {response}" if is_scam else f"✅ Safe: {response}"
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {"chat_id": chat_id, "text": reply}
        requests.post(url, json=payload)
    return "OK"

# Routes
@app.route('/', methods=['GET', 'POST'])
def home():
    message = ""
    result = ""
    is_scam = False
    scam_data = load_scam_data()
    analytics = load_analytics()
    
    # Load all ads
    ads = load_ads()
    
    if request.method == 'POST':
        message = request.form['message']
        is_scam, result = is_scam_message(message, scam_data)
        analytics['total_scans'] += 1
        if is_scam:
            analytics['scams_detected'] += 1
        analytics['last_scan'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_analytics(analytics)
    
    return render_template('home.html', 
                         message=message, 
                         result=result, 
                         is_scam=is_scam,
                         scam_data=scam_data, 
                         analytics=analytics,
                         ads=ads)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please login to access dashboard")
        return redirect('/')
    scam_data = load_scam_data()
    analytics = load_analytics()
    return render_template('dashboard.html', scam_data=scam_data, analytics=analytics, user=session['user'])

@app.route('/admin')
def admin_panel():
    if not is_admin():
        flash("Admin access required")
        return redirect('/')
    scam_data = load_scam_data()
    users = load_users()
    return render_template('admin.html', scam_data=scam_data, users=users)

@app.route('/export')
def export_data():
    if 'user' not in session:
        flash("Login required to export data")
        return redirect('/')
    return send_file(DATA_FILE, as_attachment=True)

@app.route('/import', methods=['POST'])
def import_data():
    if not is_admin():
        flash("Only admin can import data")
        return redirect('/')
    file = request.files['file']
    if file and file.filename.endswith('.json'):
        data = json.load(file)
        save_scam_data(data)
        flash("Data imported successfully")
    else:
        flash("Invalid file")
    return redirect('/admin')

@app.route('/report', methods=['POST'])
def report():
    term = request.form['term']
    category = request.form['category']
    scam_data = load_scam_data()
    if term not in scam_data[category]:
        scam_data[category].append(term)
        save_scam_data(scam_data)
        flash("Term successfully added.")
    return redirect('/')

@app.route('/delete', methods=['POST'])
def delete():
    if 'user' not in session:
        flash("Login required to delete terms.")
        return redirect('/')
    term = request.form['term']
    category = request.form['category']
    scam_data = load_scam_data()
    if term in scam_data[category]:
        scam_data[category].remove(term)
        save_scam_data(scam_data)
        flash(f"Successfully deleted '{term}' from {category}.")
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    users = load_users()
    hashed = hash_password(password)
    if username in users:
        if users[username] != hashed:
            return "Incorrect password", 403
    else:
        users[username] = hashed
        save_users(users)
    session['user'] = username
    flash("Logged in successfully.")
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully.")
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
