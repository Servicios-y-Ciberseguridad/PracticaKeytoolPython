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
- En Windows, usa el Python oficial de python.org para crear el entorno virtual

## Instalación

1. Clona o descarga este repositorio.
2. Crea un entorno virtual con el Python oficial de Windows:

```bash
py -3.14 -m venv .venv
```

3. Activa el entorno virtual:

- Windows (PowerShell):

```powershell
.\.venv\Scripts\Activate.ps1
```

- Windows (CMD):

```cmd
.venv\Scripts\activate.bat
```

4. Instala las dependencias:

```bash
pip install -r requirements.txt
```

Si ya tienes un entorno creado con MSYS2 o MinGW, recrealo con el Python oficial de Windows para poder instalar `cryptography` sin errores de compatibilidad.

## Dependencias

Este proyecto usa la librería `cryptography`, que permite generar claves, certificados y manejar operaciones criptográficas modernas de forma segura.

## Estructura del proyecto

```text
Pr-cticaKeytoolPython/
├── mykeytool.py          # Programa principal
├── README.md            # Documentación del proyecto
├── requirements.txt     # Dependencias del proyecto
├── .venv/               # Entorno virtual recomendado
├── env/                 # Entorno virtual antiguo (opcional)
└── .gitignore           # Archivos ignorados por Git
```

## Uso previsto

Si ejecutas el programa sin parametros, muestra solo los comandos disponibles:

```bash
python mykeytool.py
```

Para ver la ayuda especifica de `genkeypair`, usa:

```bash
python mykeytool.py -genkeypair -h
python mykeytool.py -genkeypair --help
```

El flujo mas simple para generar un par de claves es:

```bash
python mykeytool.py --genkeypair -keyalg RSA
python mykeytool.py --certreq
```

Tambien admite una sintaxis parecida a `keytool` para `genkeypair`:

```bash
python mykeytool.py -genkeypair -alias mykey -keyalg RSA -keysize 2048 -storepass test-password-123 -keypass test-password-123 -dname "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=ES"
```

`--genkeypair` y `-genkeypair` aceptan parametros estilo `keytool`, pero tambien completan por consola los que falten. En el flujo interactivo actual se solicitan, segun falten:

- `keyalg`
- `keysize` con valor por defecto `2048`
- contrasena del KeyStore
- contrasena de la clave (`RETURN` reutiliza la del KeyStore)
- alias con valor por defecto `mykey`
- DN: `CN`, `OU`, `O`, `L`, `ST` y `C`

En los campos interactivos del DN se puede pulsar `Enter` para dejar el valor vacio. En ese caso, el programa guarda `Unknown` en ese campo. Antes de crear el archivo, siempre muestra un resumen del DN y pide confirmacion final con `yes` o `no`.

La clave privada se guarda cifrada con `keypass`. Si `python` apunta a un interprete sin `cryptography`, el script intentara reejecutarse automaticamente con `.venv`. `--certreq` sigue siendo un marcador para la siguiente fase del proyecto.

Si quieres forzar manualmente el interprete del entorno virtual, usa:

```powershell
.\.venv\Scripts\python.exe .\mykeytool.py --genkeypair -keyalg RSA
```

## Ejemplo de funcionalidad

Se espera que el proyecto permita, como mínimo:

- Generar claves RSA.
- Mostrar información del almacén de claves.
- Identificar cada clave mediante un alias.
- Guardar y recuperar la información de forma segura.

## Nota

Este repositorio está pensado como una práctica académica y puede ir ampliándose según el enunciado concreto del ejercicio.
