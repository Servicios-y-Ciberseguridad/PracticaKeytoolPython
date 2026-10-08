# Pr-cticaKeytoolPython
Es una práctica en la que necesitamos hacer un programa .py que sea como la de Keytool en Java

## Instalacion

Requiere Python 3.10 o superior. Se recomienda usar un entorno virtual:

```powershell
python -m venv env
.\env\Scripts\Activate.ps1
pip install -r requirements.txt
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
