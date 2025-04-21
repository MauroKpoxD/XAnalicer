# scanner_core/port_scanning.py
import socket
from scapy.all import IP, TCP, UDP, sr1, ICMP

def escanear_puerto_tcp(ip, puerto, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        resultado = sock.connect_ex((ip, puerto))
        sock.close()
        return resultado == 0
    except socket.error:
        return False

def escanear_puerto_udp(ip, puerto, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (ip, puerto))
        try:
            _, _ = sock.recvfrom(1024)
            return True  # Recibimos alguna respuesta, podría estar abierto o filtrado
        except socket.timeout:
            return True  # No respuesta, podría estar abierto o filtrado
        finally:
            sock.close()
    except socket.error:
        return False

def syn_scan(target_ip, target_port, timeout=0.2):
    ip_layer = IP(dst=target_ip)
    tcp_syn = TCP(dport=target_port, flags="S")
    packet = ip_layer / tcp_syn
    response = sr1(packet, timeout=timeout, verbose=0)

    if response and response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        if tcp_layer.flags == "SA":
            return "abierto"
        elif tcp_layer.flags == "R":
            return "cerrado"
    elif response and response.haslayer(ICMP):
        icmp_layer = response.getlayer(ICMP)
        if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
            return "filtrado"
    return "filtrado o sin respuesta"