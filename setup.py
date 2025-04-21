from setuptools import setup, find_packages

setup(
    name='nombre_de_tu_proyecto',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'scapy',  # Lista las dependencias de tu proyecto
        'argparse',
        # ... otras dependencias
    ],
    entry_points={
        'console_scripts': [
            'XAnalicer=cli.main:main',
        ],
    },
    author='Tu Nombre',
    author_email='tu_email@example.com',
    description='Un escáner de red simple en Python',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/tu_usuario/nombre_de_tu_proyecto', # Reemplaza con la URL de tu repo
    license='MIT', # Reemplaza con tu licencia
)