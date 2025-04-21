# scanner_core/utils.py
def parse_ports(ports_string):
    ports = []
    parts = ports_string.split(',')
    for part in parts:
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            except ValueError:
                print(f"Advertencia: Rango de puertos inválido: {part}")
        else:
            try:
                ports.append(int(part))
            except ValueError:
                print(f"Advertencia: Puerto inválido: {part}")
    return sorted(list(set(ports)))