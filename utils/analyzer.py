from datetime import datetime

# Track attempt counts per IP
ip_tracker = {}

# Alert thresholds
THRESHOLDS = {
    'CRITICAL': 20,
    'HIGH': 10,
    'MEDIUM': 3,
    'LOW': 1
}

def analyze_attempt(ip, username, password, attack_log):
    """Analyze an attack attempt and classify it."""

    if ip not in ip_tracker:
        ip_tracker[ip] = {
            'count': 0,
            'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'usernames': [],
            'passwords': []
        }

    ip_tracker[ip]['count'] += 1
    ip_tracker[ip]['usernames'].append(username)
    ip_tracker[ip]['passwords'].append(password)

    attempt_count = ip_tracker[ip]['count']
    unique_passwords = len(set(ip_tracker[ip]['passwords']))
    unique_usernames = len(set(ip_tracker[ip]['usernames']))

    # Classify attacker type
    if attempt_count == 1:
        attacker_type = 'Single Probe'
    elif unique_usernames > 5:
        attacker_type = 'Credential Stuffing'
    elif unique_passwords > 10:
        attacker_type = 'Brute Force'
    elif attempt_count > 3 and unique_usernames <= 2:
        attacker_type = 'Targeted Attack'
    else:
        attacker_type = 'Automated Scanner'

    # Assign severity based on thresholds
    if attempt_count >= THRESHOLDS['CRITICAL']:
        severity = 'CRITICAL'
    elif attempt_count >= THRESHOLDS['HIGH']:
        severity = 'HIGH'
    elif attempt_count >= THRESHOLDS['MEDIUM']:
        severity = 'MEDIUM'
    else:
        severity = 'LOW'

    # Generate alert message if threshold crossed
    alert = None
    if attempt_count == THRESHOLDS['CRITICAL']:
        alert = f"CRITICAL THRESHOLD REACHED — {ip} has made {attempt_count} attempts"
    elif attempt_count == THRESHOLDS['HIGH']:
        alert = f"HIGH THRESHOLD REACHED — {ip} has made {attempt_count} attempts"
    elif attempt_count == THRESHOLDS['MEDIUM']:
        alert = f"MEDIUM THRESHOLD REACHED — {ip} has made {attempt_count} attempts"

    return {
        'severity': severity,
        'attacker_type': attacker_type,
        'attempt_count': attempt_count,
        'alert': alert,
        'first_seen': ip_tracker[ip]['first_seen']
    }