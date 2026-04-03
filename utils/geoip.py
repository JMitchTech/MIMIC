import requests

def get_geo(ip):
    """Get geolocation data for an IP address using the free ip-api.com service."""
    
    # Don't look up private/local IP addresses
    if ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('127.') or ip == '0.0.0.0':
        return {
            'country': 'Local Network',
            'city': 'Local',
            'isp': 'Local'
        }

    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()

        if data['status'] == 'success':
            return {
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown')
            }
        else:
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'isp': 'Unknown'
            }

    except Exception:
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown'
        }