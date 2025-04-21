# scanner_core/host_discovery.py
import subprocess
import platform
import ipaddress
from scapy.all import IP, ICMP, sr1, Ether, ARP, srp

def ping(host, timeout=1, count=1):
    """
    Realiza un ping al host utilizando la utilidad del sistema operativo.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, str(count), '-w', str(int(timeout * 1000)), host]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        print("Error: El comando 'ping' no se encontró en el sistema.")
        return False

def ping_scapy(host, timeout=1):
    """
    Realiza un ping al host enviando un paquete ICMP Echo Request usando Scapy.
    """
    try:
        icmp_request = IP(dst=host) / ICMP()
        icmp_reply = sr1(icmp_request, timeout=timeout, verbose=0)
        return icmp_reply is not None and icmp_reply.haslayer(ICMP) and icmp_reply.getlayer(ICMP).type == 0
    except PermissionError:
        print("Error: Se necesitan permisos de administrador/root para enviar paquetes raw con Scapy.")
        return False
    except Exception as e:
        print(f"Error al enviar ping con Scapy a {host}: {e}")
        return False

def discover_hosts_arp_scan(interface, network_cidr, timeout=1):
    """
    Descubre hosts activos en una red local usando escaneo ARP.
    """
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network.hosts())
        answered, _ = srp(arp_request, timeout=timeout, iface=interface, verbose=0)
        hosts = [received.psrc for sent, received in answered]
        print(f"Realizando escaneo ARP en la interfaz '{interface}' y red '{network}'")
        return hosts
    except ImportError:
        print("Error: La biblioteca Scapy no está instalada. Instálala con 'pip install scapy'.")
        return []
    except PermissionError:
        print("Error: Se necesitan permisos de administrador/root para realizar escaneos ARP.")
        return []
    except Exception as e:
        print(f"Error al realizar escaneo ARP: {e}")
        return []

if __name__ == "__main__":
    print("Este es el módulo host_discovery. Puede ser importado por otros scripts.")

    target_ip = "192.168.1.1"
    if ping(target_ip):
        print(f"El host {target_ip} está activo (usando ping del sistema).")
    else:
        print(f"El host {target_ip} no responde al ping del sistema.")

    if ping_scapy(target_ip):
        print(f"El host {target_ip} está activo (usando ping con Scapy).")
    else:
        print(f"El host {target_ip} no responde al ping con Scapy.")

    # Ejemplo de cómo se llamaría desde scanner.py (la lógica de ping sweep estaría allí)
    # network_to_scan = "192.168.1.0/24"
    # print(f"\nHosts activos en {network_to_scan} (usando ping sweep):")
    # for host in scanner.perform_ping_sweep(network_to_scan, verbose=True, timeout=0.5):
    #     print(f"- {host}")

    # Ejemplo de uso de discover_hosts_arp_scan
    # interface_name = "eth0"
    # network_to_scan = "192.168.1.0/24"
    # print(f"\nHosts activos en {network_to_scan} (usando escaneo ARP en {interface_name}):")
    # hosts_arp = discover_hosts_arp_scan(interface_name, network_to_scan, timeout=0.5)
    # for host in hosts_arp:
    #     print(f"- {host}")