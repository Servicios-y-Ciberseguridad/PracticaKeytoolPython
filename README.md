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

## Generar un par de claves

```powershell
python mykeytool.py --genkeypair
python mykeytool.py --genkeypair --keystore personal.myks
```

La operacion solicita una contrasena sin eco, un alias unico y los campos
DN CN, OU, O, L, ST y C. Todos son obligatorios; C debe contener dos letras
(por ejemplo, ES). Los alias distinguen mayusculas y minusculas.
Para un almacen nuevo, la contrasena debe tener al menos ocho caracteres y
se solicita confirmacion. Si no hay un terminal que permita ocultarla, la
operacion falla en lugar de mostrar la contrasena.

Se genera una clave RSA de **2048 bits**, con exponente publico 65537.
La entrada contiene la clave privada PKCS#8, la publica y los campos DN.
No se genera un certificado. Las entradas existentes se conservan y los
alias duplicados se rechazan sin modificar el archivo.

Por defecto se utiliza `keystore.myks` en el directorio de trabajo.
Es un **formato propio, no compatible con JKS ni PKCS#12**:
todo el contenido (incluidas claves, alias y DN) se cifra y autentica con
AES-256-GCM. La clave de cifrado se deriva de la contrasena mediante scrypt
(N=131072, r=8, p=1), con sal aleatoria de 16 bytes. Cada escritura utiliza
una nueva sal y un nonce aleatorio de 12 bytes. Un temporal cifrado en el
mismo directorio se reemplaza atomicamente para evitar archivos parciales.
Utiliza una contrasena larga y unica y restringe los permisos del directorio
con las herramientas del sistema operativo. No ejecutes escritores
simultaneos sobre el mismo almacen.

Se informa de exito o error; los codigos de salida son 0 y 1 respectivamente
(2 para argumentos incorrectos). Una contrasena incorrecta, un archivo
alterado o un fallo de escritura no se notifican como exito.
La opcion `--certreq` sigue siendo un punto de entrada pendiente de implementar.

## Pruebas

```powershell
python -m unittest discover -s tests -v
```

## Ejemplo de funcionalidad

Se espera que el proyecto permita, como mínimo:

- Generar claves RSA.
- Mostrar información del almacén de claves.
- Identificar cada clave mediante un alias.
- Guardar y recuperar la información de forma segura.

## Nota

Este repositorio está pensado como una práctica académica y puede ir ampliándose según el enunciado concreto del ejercicio.
