# Práctica Keytool en Python

Este proyecto consiste en una implementación en Python de una herramienta similar a `keytool`, la utilidad de Java para gestionar claves y certificados digitales.

La idea de la práctica es aprender a trabajar con criptografía, generación de claves, y manejo básico de certificados en un entorno CLI.

## Objetivo

Crear un programa Python que permita:

- Generar pares de claves pública/privada.
- Almacenar claves con alias identificativos.
- Exportar y leer información asociada a los certificados.
- Simular funcionalidades básicas de `keytool` en un entorno de consola.

## Requisitos

- Python 3.10 o superior
- pip
- Entorno virtual recomendado

## Instalación

1. Clona o descarga este repositorio.
2. Crea un entorno virtual:

```bash
python -m venv env
```

3. Activa el entorno virtual:

- Windows (PowerShell):

```powershell
.\env\Scripts\Activate.ps1
```

- Windows (CMD):

```cmd
env\Scripts\activate.bat
```

4. Instala las dependencias:

```bash
pip install -r requirements.txt
```

## Dependencias

Este proyecto usa la librería `cryptography`, que permite generar claves, certificados y manejar operaciones criptográficas modernas de forma segura.

## Estructura del proyecto

```text
Pr-cticaKeytoolPython/
├── mykeytool.py          # Programa principal
├── README.md            # Documentación del proyecto
├── requirements.txt     # Dependencias del proyecto
├── env/                 # Entorno virtual (opcional)
└── .gitignore           # Archivos ignorados por Git
```

## Uso previsto

El programa se ejecutará desde la línea de comandos y podría tener un comportamiento parecido a:

```bash
python mykeytool.py --generate-key --alias miClave --keysize 2048
python mykeytool.py --list
python mykeytool.py --export --alias miClave
```

Las opciones reales pueden variar según la implementación final, pero la idea es mantener la lógica de gestión de claves y certificados similar a la de `keytool`.

## Ejemplo de funcionalidad

Se espera que el proyecto permita, como mínimo:

- Generar claves RSA.
- Mostrar información del almacén de claves.
- Identificar cada clave mediante un alias.
- Guardar y recuperar la información de forma segura.

## Nota

Este repositorio está pensado como una práctica académica y puede ir ampliándose según el enunciado concreto del ejercicio.
