import socket
import threading
import paramiko
import logging
import os
import time

# Suppress paramiko's own logging
logging.getLogger('paramiko').setLevel(logging.CRITICAL)

# Key file path
KEY_FILE = 'data/host_key.key'

def get_host_key():
    """Load existing host key or generate and save a new one."""
    os.makedirs('data', exist_ok=True)
    if os.path.exists(KEY_FILE):
        return paramiko.RSAKey(filename=KEY_FILE)
    else:
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(KEY_FILE)
        print("[MIMIC] Generated new host key and saved to disk.")
        return key

HOST_KEY = get_host_key()

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port, callback):
        self.client_ip = client_ip
        self.client_port = client_port
        self.callback = callback
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.callback(self.client_ip, self.client_port, username, password, 'SSH')
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'


def handle_ssh_connection(client_socket, client_address, callback):
    """Handle a single incoming SSH connection."""
    ip, port = client_address
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'
        transport.add_server_key(HOST_KEY)
        fake_server = FakeSSHServer(ip, port, callback)
        transport.start_server(server=fake_server)
        channel = transport.accept(30)
        if channel:
            channel.close()
    except Exception:
        pass
    finally:
        if transport:
            try:
                transport.close()
            except:
                pass
        try:
            client_socket.close()
        except:
            pass


def handle_telnet_connection(client_socket, client_address, callback):
    """Fake Telnet server."""
    ip, port = client_address
    try:
        client_socket.settimeout(30)
        client_socket.send(b'\r\nWelcome to Ubuntu 22.04 LTS\r\n\r\nlogin: ')
        username = b''
        while True:
            ch = client_socket.recv(1)
            if not ch or ch == b'\n' or ch == b'\r':
                break
            username += ch

        client_socket.send(b'Password: ')
        password = b''
        while True:
            ch = client_socket.recv(1)
            if not ch or ch == b'\n' or ch == b'\r':
                break
            password += ch

        username = username.decode('utf-8', errors='ignore').strip()
        password = password.decode('utf-8', errors='ignore').strip()

        if username and password:
            callback(ip, port, username, password, 'TELNET')

        client_socket.send(b'\r\nLogin incorrect\r\n')
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except:
            pass


def handle_ftp_connection(client_socket, client_address, callback):
    """Fake FTP server."""
    ip, port = client_address
    try:
        client_socket.settimeout(60)
        client_socket.send(b'220 Microsoft FTP Service\r\n')
        username = ''
        password = ''
        buffer = ''

        while True:
            try:
                chunk = client_socket.recv(1024).decode('utf-8', errors='ignore')
                if not chunk:
                    break
                buffer += chunk
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue
                    if line.upper().startswith('USER'):
                        username = line[4:].strip()
                        client_socket.send(b'331 Password required for ' + username.encode() + b'\r\n')
                    elif line.upper().startswith('PASS'):
                        password = line[4:].strip()
                        if username:
                            callback(ip, port, username, password, 'FTP')
                        client_socket.send(b'530 Login incorrect.\r\n')
                        return
                    elif line.upper() == 'QUIT':
                        client_socket.send(b'221 Goodbye.\r\n')
                        return
            except Exception:
                break
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except:
            pass


def handle_rdp_connection(client_socket, client_address, callback):
    """Fake RDP — logs the connection attempt."""
    ip, port = client_address
    try:
        client_socket.settimeout(10)
        # RDP sends a connection request — we just log the probe
        data = client_socket.recv(1024)
        if data:
            callback(ip, port, 'rdp_probe', 'N/A', 'RDP')
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except:
            pass


def handle_tarpit_connection(client_socket, client_address, callback):
    """Tarpit — accepts connection and drips data to waste attacker's time."""
    ip, port = client_address
    try:
        callback(ip, port, 'tarpit_probe', 'N/A', 'TARPIT')
        # Drip one byte every 30 seconds to keep attacker hanging
        for _ in range(20):
            time.sleep(30)
            client_socket.send(b'.')
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except:
            pass


def start_listener(host, port, handler, callback, service_name):
    """Generic TCP listener for any service."""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(100)
        print(f"[MIMIC] {service_name} honeypot active on {host}:{port}")

        while True:
            try:
                client_socket, client_address = server_socket.accept()
                thread = threading.Thread(
                    target=handler,
                    args=(client_socket, client_address, callback),
                    daemon=True
                )
                thread.start()
            except Exception:
                pass
    except Exception as e:
        print(f"[MIMIC] Could not start {service_name} on port {port}: {e}")


class SSHHoneypot:
    """Main honeypot manager — starts all listeners."""

    def __init__(self, host='0.0.0.0', callback=None):
        self.host = host
        self.callback = callback

    def start(self):
        services = [
            (2222, handle_ssh_connection,    'SSH'),
            (23,   handle_telnet_connection, 'TELNET'),
            (21,   handle_ftp_connection,    'FTP'),
            (3389, handle_rdp_connection,    'RDP'),
            (9999, handle_tarpit_connection, 'TARPIT'),
        ]

        threads = []
        for port, handler, name in services:
            t = threading.Thread(
                target=start_listener,
                args=(self.host, port, handler, self.callback, name),
                daemon=True
            )
            t.start()
            threads.append(t)

        # Keep main thread alive
        for t in threads:
            t.join()