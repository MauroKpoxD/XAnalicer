# cli/main.py
import sys
import os
import argparse
import socket
import requests
import logging
import ipaddress
from scapy.config import conf as scapy_conf

scapy_conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root_dir)

from scanner_core.scanner import (
    perform_ping_sweep,
    perform_arp_scan,
    perform_syn_scan,
    perform_tcp_connect_scan,
    perform_udp_scan,
)
from scanner_core.utils import parse_ports

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=3)
        response.raise_for_status()
        return response.json()['ip']
    except requests.exceptions.RequestException:
        return "No se pudo obtener la IP pública"

def get_private_ip():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return "No se pudo obtener la IP privada"

def display_info(parser):
    public_ip = get_public_ip()
    private_ip = get_private_ip()
    print("#################################################")
    print(f"{'IP:':<15} {public_ip}")
    print(f"{'IP Privada:':<15} {private_ip}")
    print("#################################################\n")
    print("Uso: python main.py [opciones] <objetivo>\n")
    print("Opciones:")
    print(parser.format_help())

def validate_target(target):
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            ipaddress.ip_network(target, strict=False)
            return target
        except ValueError:
            return None

def validate_ports(ports_string):
    ports = parse_ports(ports_string)
    validated_ports = [p for p in ports if 1 <= p <= 65535]
    if len(validated_ports) != len(ports):
        print("Advertencia: Algunos puertos especificados están fuera del rango válido (1-65535) y fueron ignorados.")
    return ",".join(map(str, validated_ports))

def validate_timeout(timeout):
    try:
        timeout_float = float(timeout)
        if timeout_float > 0:
            return timeout_float
        else:
            return 1.0
    except ValueError:
        return 1.0

def run_ping_sweep(target, verbose, timeout):
    print("[*] Ejecutando Ping Sweep...")
    perform_ping_sweep(target, verbose, timeout)

def run_arp_scan(interface, target, verbose, timeout):
    print("[*] Ejecutando Escaneo ARP...")
    perform_arp_scan(interface, target, verbose, timeout)

def run_syn_scan(target, ports, verbose, vulnerability, timeout):
    print("[*] Ejecutando Escaneo SYN...")
    perform_syn_scan(target, ports, verbose, vulnerability, timeout)

def run_tcp_connect_scan(target, ports, verbose, vulnerability, timeout):
    print("[*] Ejecutando Escaneo TCP Connect...")
    perform_tcp_connect_scan(target, ports, verbose, vulnerability, timeout)

def run_udp_scan(target, ports, verbose, timeout):
    print("[*] Ejecutando Escaneo UDP...")
    perform_udp_scan(target, ports, verbose, timeout)

def main():
    parser = argparse.ArgumentParser(description="XAnalicer: Una herramienta de análisis de red.")
    parser.add_argument("target", nargs='?', help="Dirección IP o rango de IPs objetivo.")
    parser.add_argument("-p", "--ports", help="Lista de puertos a escanear (ej: 80,443,1-100).", default="1-1024")
    parser.add_argument("-sP", "--ping", action="store_true", help="Realizar un ping sweep para descubrimiento de hosts.")
    parser.add_argument("-sS", "--syn", action="store_true", help="Realizar un escaneo SYN de puertos TCP.")
    parser.add_argument("-sT", "--tcp", action="store_true", help="Realizar un escaneo TCP Connect de puertos.")
    parser.add_argument("-sU", "--udp", action="store_true", help="Realizar un escaneo UDP de puertos.")
    parser.add_argument("-i", "--interface", help="Interfaz de red para escaneo ARP.", default=None)
    parser.add_argument("-vuln", "--vulnerability", action="store_true", help="Realizar una detección básica de vulnerabilidades.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostrar información detallada.")
    parser.add_argument("-oN", "--output-normal", metavar="FILE", help="Guardar la salida en formato normal a un archivo (no implementado).")
    parser.add_argument("-oJ", "--output-json", metavar="FILE", help="Guardar la salida en formato JSON a un archivo (no implementado).")
    parser.add_argument("--timeout", type=float, default=1.0, help="Tiempo de espera (en segundos) para las respuestas.")
    args = parser.parse_args()

    scapy_conf.iface = args.interface

    if args.target is None and not any([args.ping, args.syn, args.tcp, args.udp, args.interface, args.vulnerability]):
        display_info(parser)
    elif args.target:
        target = validate_target(args.target)
        if not target:
            print(f"Error: El objetivo '{args.target}' no es una dirección IP o rango válido.")
            sys.exit(1)

        ports_string = validate_ports(args.ports)
        ports = parse_ports(ports_string)
        timeout = validate_timeout(args.timeout)

        print("-------------------------------------------------")
        print(f"[*] Objetivo: {target}")
        print(f"[*] Puertos: {ports_string}")
        print(f"[*] Timeout: {timeout} segundos")
        print("-------------------------------------------------")

        scan_actions = {
            args.ping: lambda: run_ping_sweep(target, args.verbose, timeout),
            args.interface: lambda: run_arp_scan(args.interface, target, args.verbose, timeout),
            args.syn: lambda: run_syn_scan(target, ports, args.verbose, args.vulnerability, timeout),
            args.tcp: lambda: run_tcp_connect_scan(target, ports, args.verbose, args.vulnerability, timeout),
            args.udp: lambda: run_udp_scan(target, ports, args.verbose, timeout),
        }

        executed_scan = False
        for condition, action in scan_actions.items():
            if condition:
                action()
                executed_scan = True
                break  # Solo ejecutar un tipo de escaneo a la vez por ahora

        if args.vulnerability and not executed_scan:
            print("Advertencia: La opción -vuln solo tiene sentido con un escaneo de puertos (-sS, -sT, -sU).")
        elif not executed_scan:
            parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()