# scanner_core/service_detection.py
import socket

def detect_service(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner
    except OSError: # Capturamos OSError
        return None