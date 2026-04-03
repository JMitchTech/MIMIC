from flask import Flask, render_template, jsonify, Response
from flask_socketio import SocketIO, emit
import threading
import json
import csv
import io
import os
from datetime import datetime
from utils.honeypot import SSHHoneypot
from utils.analyzer import analyze_attempt
from utils.geoip import get_geo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mimic_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Log file path
LOG_FILE = 'logs/attacks.json'

def load_attacks():
    """Load existing attacks from disk."""
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_attacks(attacks):
    """Save attacks to disk."""
    os.makedirs('logs', exist_ok=True)
    with open(LOG_FILE, 'w') as f:
        json.dump(attacks, f, indent=2)

# Load existing attacks on startup
attack_log = load_attacks()

def broadcast_attempt(attempt):
    """Send new attack attempt to all connected dashboard clients."""
    socketio.emit('new_attempt', attempt)

def on_ssh_attempt(ip, port, username, password, service='SSH'):
    """Called by the honeypot engine every time a login attempt is made."""
    geo = get_geo(ip)
    analysis = analyze_attempt(ip, username, password, attack_log)

    attempt = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': ip,
        'port': port,
        'service': service,
        'username': username,
        'password': password,
        'country': geo.get('country', 'Unknown'),
        'city': geo.get('city', 'Unknown'),
        'isp': geo.get('isp', 'Unknown'),
        'severity': analysis['severity'],
        'attacker_type': analysis['attacker_type'],
        'attempt_count': analysis['attempt_count']
    }

    attack_log.insert(0, attempt)
    save_attacks(attack_log)
    broadcast_attempt(attempt)

    # Broadcast threshold alert if one was triggered
    if analysis.get('alert'):
        print(f"[ALERT] Emitting threshold alert: {analysis['alert']}")
        socketio.emit('threshold_alert', {
            'message': analysis['alert'],
            'severity': analysis['severity'],
            'ip': ip
        })

@app.route('/')
def index():
    return render_template('index.html', attacks=attack_log)

@app.route('/api/attacks')
def get_attacks():
    return jsonify(attack_log)

@app.route('/api/stats')
def get_stats():
    if not attack_log:
        return jsonify({
            'total': 0,
            'unique_ips': 0,
            'top_username': 'N/A',
            'top_country': 'N/A'
        })

    unique_ips = len(set(a['ip'] for a in attack_log))
    top_username = max(set(a['username'] for a in attack_log),
                      key=lambda u: sum(1 for a in attack_log if a['username'] == u))
    top_country = max(set(a['country'] for a in attack_log),
                     key=lambda c: sum(1 for a in attack_log if a['country'] == c))

    return jsonify({
        'total': len(attack_log),
        'unique_ips': unique_ips,
        'top_username': top_username,
        'top_country': top_country
    })

@app.route('/api/export/csv')
def export_csv():
    """Export attack log as CSV download."""
    if not attack_log:
        return "No data to export", 404

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'timestamp', 'ip', 'port', 'username', 'password',
        'country', 'city', 'isp', 'severity', 'attacker_type', 'attempt_count'
    ])
    writer.writeheader()
    writer.writerows(attack_log)

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=mimic_attacks.csv'}
    )

@app.route('/api/clear')
def clear_log():
    """Clear the attack log and reset the analyzer tracker."""
    global attack_log
    from utils.analyzer import ip_tracker
    attack_log = []
    ip_tracker.clear()
    save_attacks(attack_log)
    return jsonify({'status': 'cleared'})

if __name__ == '__main__':
    honeypot = SSHHoneypot(host='0.0.0.0', callback=on_ssh_attempt)
    honeypot_thread = threading.Thread(target=honeypot.start, daemon=True)
    honeypot_thread.start()
    print("MIMIC honeypot listening on port 2222")
    print("MIMIC dashboard running on http://127.0.0.1:5002")
    socketio.run(app, host='0.0.0.0', port=5002, debug=False)