## Estructura del Proyecto

XAnalicer/
├── scanner_core/
│   ├── __init__.py
│   ├── host_discovery.py
│   ├── port_scanning.py
│   ├── service_detection.py
│   ├── vulnerability_scanner.py
│   └── utils.py
├── cli/
│   ├── __init__.py
│   └── main.py
├── README.md
├── LICENSE
├── setup.py
└── requirements.txt
└── .gitignore

* **`XAnalicer/` (Directorio Raíz):**
    * Es el directorio principal que contiene todos los archivos y carpetas del proyecto XAnalicer.

* **`scanner_core/` (Directorio):**
    * Este directorio alberga la lógica principal del escáner de red. Contiene los módulos responsables de las diferentes funcionalidades de escaneo.
        * **`__init__.py`:** Un archivo especial que indica a Python que el directorio `scanner_core` debe ser tratado como un paquete. Puede estar vacío o contener inicializaciones del paquete.
        * **`host_discovery.py`:** Contiene funciones relacionadas con el descubrimiento de hosts en una red, como la implementación de ping (ICMP) y escaneo ARP.
        * **`port_scanning.py`:** Incluye funciones para realizar diferentes tipos de escaneo de puertos (TCP Connect, SYN Scan, UDP Scan) en un host objetivo.
        * **`service_detection.py`:** Contiene funciones para intentar identificar los servicios que se están ejecutando en los puertos abiertos, generalmente mediante el análisis de banners de respuesta.
        * **`vulnerability_scanner.py`:** Implementa una lógica básica para verificar si los banners de servicio detectados coinciden con vulnerabilidades conocidas (actualmente una lista estática y simplificada).
        * **`utils.py`:** Contiene funciones de utilidad que son utilizadas por otros módulos dentro de `scanner_core`, como la función `parse_ports` para procesar la lista de puertos proporcionada por el usuario.

* **`cli/` (Directorio):**
    * Este directorio contiene los archivos relacionados con la interfaz de línea de comandos (CLI) de XAnalicer.
        * **`__init__.py`:** Similar al `__init__.py` en `scanner_core`, este archivo marca el directorio `cli` como un paquete de Python.
        * **`main.py`:** Es el script principal que se ejecuta para iniciar XAnalicer desde la terminal. Utiliza la biblioteca `argparse` para definir y manejar los argumentos y opciones de la línea de comandos, e importa y utiliza las funciones del paquete `scanner_core` para realizar las tareas de escaneo.

* **`README.md` (Archivo):**
    * Este archivo (en formato Markdown) proporciona una descripción general del proyecto XAnalicer. Incluye información sobre qué es la herramienta, cómo instalarla, cómo usarla, la estructura del proyecto, posibles contribuciones, información de licencia, etc. Es la primera página que la gente verá en plataformas como GitHub.

* **`LICENSE` (Archivo):**
    * Este archivo contiene la licencia bajo la cual se distribuye el proyecto XAnalicer (ej: MIT, Apache 2.0). Es importante para definir los términos de uso, modificación y distribución del código.

* **`setup.py` (Archivo):**
    * Este script de Python se utiliza para empaquetar e instalar el proyecto XAnalicer. Define el nombre del paquete, la versión, las dependencias (listadas en `requirements.txt`), el punto de entrada para la línea de comandos (`cli.main:main`), y otra información relevante para la distribución.

* **`requirements.txt` (Archivo):**
    * Este archivo lista todas las dependencias (bibliotecas de Python) necesarias para ejecutar XAnalicer. Los usuarios pueden instalar estas dependencias fácilmente utilizando `pip install -r requirements.txt`.

* **`.gitignore` (Archivo):**
    * Este archivo especifica los archivos y directorios que Git debe ignorar y no rastrear en el repositorio. Esto puede incluir archivos temporales, archivos de caché de Python (`.pyc`, `__pycache__`), archivos de entorno virtual, etc.
    
## Ejemplo de uso:

usage: main.py [-h] [-p PORTS] [-sP] [-sS] [-sT] [-sU] [-i INTERFACE] [-vuln] [-v] [-oN FILE] [-oJ FILE] [--timeout TIMEOUT] [target]

XAnalicer: Una herramienta de análisis de red.

positional arguments:
  target                Dirección IP o rango de IPs objetivo.

[options]

  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Lista de puertos a escanear (ej: 80,443,1-100).
  -sP, --ping           Realizar un ping sweep para descubrimiento de hosts.
  -sS, --syn            Realizar un escaneo SYN de puertos TCP.
  -sT, --tcp            Realizar un escaneo TCP Connect de puertos.
  -sU, --udp            Realizar un escaneo UDP de puertos.
  -i INTERFACE, --interface INTERFACE
                        Interfaz de red para escaneo ARP.
  -vuln, --vulnerability
                        Realizar una detección básica de vulnerabilidades.
  -v, --verbose         Mostrar información detallada.
  -oN FILE, --output-normal FILE
                        Guardar la salida en formato normal a un archivo (no implementado).
  -oJ FILE, --output-json FILE
                        Guardar la salida en formato JSON a un archivo (no implementado).
  --timeout TIMEOUT     Tiempo de espera (en segundos) para las respuestas.

* **Comando** (python cli/main.py [option] [Ip_Objetivo]*

python cli/main.py -sP 123.456.789/24
 
-sP, --ping: Realizar un ping sweep para descubrimiento de hosts.