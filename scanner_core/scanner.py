# scanner_core/scanner.py
import ipaddress
from scanner_core import host_discovery, port_scanning, service_detection, vulnerability_scanner
from scanner_core.utils import parse_ports

def perform_ping_sweep(target, verbose, timeout):
    print(f"[*] Realizando Ping Sweep en {target}...")
    print("-------------------------------------------------")
    try:
        ip_list = []
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            ip_list.extend(str(ip) for ip in network.hosts())
        else:
            ip_list.append(target)
        for ip in ip_list:
            if host_discovery.ping(ip, timeout=timeout):
                print(f"Host {ip:<15} está activo")
            elif verbose:
                print(f"Host {ip:<15} no responde")
    except ValueError:
        print(f"Error: '{target}' no es una dirección IP o red válida.")

def perform_arp_scan(interface, target, verbose, timeout):
    print(f"[*] Realizando Descubrimiento ARP en {target} a través de {interface}...")
    print("-------------------------------------------------")
    hosts = host_discovery.discover_hosts_arp_scan(interface, target, timeout=timeout)
    if hosts:
        for host in hosts:
            print(f"Host {host:<15} está activo (ARP)")
    elif verbose:
        print("No se encontraron hosts activos por ARP.")

def perform_syn_scan(target, ports, verbose, vulnerability, timeout):
    print(f"[*] Escaneo SYN en {target}...")
    print("-------------------------------------------------")
    print(f"{'IP':<15} {'Puerto':<10} {'Estado':<15} {'Servicio':<20}")
    try:
        for port in ports:
            status = port_scanning.syn_scan(target, port, timeout=timeout)
            if status == "abierto":
                service = service_detection.detect_service(target, port, timeout=timeout) or "Desconocido"
                print(f"{target:<15} {port:<10} {status:<15} {service:<20}")
                if vulnerability and service != "Desconocido":
                    vulnerability_check = vulnerability_scanner.check_known_vulnerabilities(service)
                    if vulnerability_check:
                        print(f"{'':<15} {'':<10} {'':<15} [*] Vulnerabilidad: {vulnerability_check}")
            elif verbose:
                print(f"{target:<15} {port:<10} {status:<15}")
    except Exception as e:
        print(f"Error durante el escaneo SYN: {e}")

def perform_tcp_connect_scan(target, ports, verbose, vulnerability, timeout):
    print(f"[*] Escaneo TCP Connect en {target}...")
    print("-------------------------------------------------")
    print(f"{'IP':<15} {'Puerto':<10} {'Estado':<15} {'Servicio':<20}")
    for port in ports:
        if port_scanning.escanear_puerto_tcp(target, port, timeout=timeout):
            service = service_detection.detect_service(target, port, timeout=timeout) or "Desconocido"
            print(f"{target:<15} {port:<10} {'abierto':<15} {service:<20}")
            if vulnerability and service != "Desconocido":
                vulnerability_check = vulnerability_scanner.check_known_vulnerabilities(service)
                if vulnerability_check:
                    print(f"{'':<15} {'':<10} {'':<15} [*] Vulnerabilidad: {vulnerability_check}")
        elif verbose:
            print(f"{target:<15} {port:<10} {'cerrado/filtrado':<15}")

def perform_udp_scan(target, ports, verbose, timeout): # Eliminamos 'vulnerability'
    print(f"[*] Escaneo UDP en {target}...")
    print("-------------------------------------------------")
    print(f"{'IP':<15} {'Puerto':<10} {'Estado':<15}")
    for port in ports:
        if port_scanning.escanear_puerto_udp(target, port, timeout=timeout):
            print(f"{target:<15} {port:<10} {'abierto/filtrado':<15}")
        elif verbose:
            print(f"{target:<15} {port:<10} {'cerrado':<15}")