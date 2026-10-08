"""Interfaz de linea de comandos para el simulador de Java Keytool."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import subprocess
import sys
import tempfile
import warnings
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TypedDict

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ModuleNotFoundError as exc:
    InvalidTag = None
    serialization = None
    rsa = None
    AESGCM = None
    Scrypt = None
    CRYPTO_IMPORT_ERROR = exc
else:
    CRYPTO_IMPORT_ERROR = None

CommandHandler = Callable[[], int]
DEFAULT_KEYSTORE = Path("keystore.myks")
STORE_HEADER = b"MYKEYSTORE\x01"
DN_FIELDS = ("CN", "OU", "O", "L", "ST", "C")
UNKNOWN_DN_VALUE = "Unknown"

class KeyEntry(TypedDict):
    private_key: str
    public_key: str
    dn: dict[str, str]

def ensure_crypto_available() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        raise ModuleNotFoundError(
            "No se pudo importar 'cryptography' con este interprete de Python."
        ) from CRYPTO_IMPORT_ERROR


class GenKeyPairOptions(TypedDict, total=False):
    alias: str
    storepass: str
    keypass: str
    dname: str
    keyalg: str
    keysize: int

def handoff_to_project_venv(argv: Sequence[str] | None) -> int | None:
    if CRYPTO_IMPORT_ERROR is None:
        return None
    venv_python = Path(__file__).with_name(".venv") / "Scripts" / "python.exe"
    current = Path(sys.executable).resolve()
    if not venv_python.exists() or current == venv_python.resolve():
        return None
    command = [str(venv_python), str(Path(__file__).resolve()), *(argv or sys.argv[1:])]
    return subprocess.run(command, check=False).returncode

def derive_store_key(password: str, salt: bytes) -> bytes:
    ensure_crypto_available()
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(
        password.encode("utf-8")
    )

def load_keystore(path: Path, password: str) -> dict[str, KeyEntry]:
    ensure_crypto_available()

    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return {}
    
    offset = len(STORE_HEADER)

    if not data.startswith(STORE_HEADER) or len(data) < offset + 16 + 12 + 16:
        raise ValueError("Formato de KeyStore no valido.")
    
    salt = data[offset : offset + 16]
    nonce = data[offset + 16 : offset + 28]

    try:
        plaintext = AESGCM(derive_store_key(password, salt)).decrypt(
            nonce, data[offset + 28 :], STORE_HEADER
        )
    except InvalidTag as exc:
        raise ValueError("Contrasena incorrecta o KeyStore alterado.") from exc
    
    entries = json.loads(plaintext)

    if not isinstance(entries, dict):
        raise ValueError("Contenido de KeyStore no valido.")
    
    store: dict[str, KeyEntry] = {}

    for alias, entry in entries.items():
        if (
            not isinstance(alias, str)
            or not alias.strip()
            or not isinstance(entry, dict)
            or not isinstance(entry.get("private_key"), str)
            or not isinstance(entry.get("public_key"), str)
            or not isinstance(entry.get("dn"), dict)
        ):
            raise ValueError("Entrada de KeyStore no valida.")
        
        dn = entry["dn"]

        if set(dn) != set(DN_FIELDS) or any(
            not isinstance(value, str) or not value.strip() for value in dn.values()
        ):
            raise ValueError("DN de KeyStore no valido.")
        
        store[alias] = KeyEntry(
            private_key=entry["private_key"], public_key=entry["public_key"], dn=dn
        )

    return store

def save_keystore(path: Path, password: str, entries: dict[str, KeyEntry]) -> None:
    ensure_crypto_available()

    salt = os.urandom(16)
    nonce = os.urandom(12)

    plaintext = json.dumps(entries, ensure_ascii=True).encode("utf-8")
    ciphertext = AESGCM(derive_store_key(password, salt)).encrypt(
        nonce, plaintext, STORE_HEADER
    )

    # El temporal solo contiene datos cifrados y se reemplaza en el mismo volumen.
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
        
        try:
            temporary.write(STORE_HEADER + salt + nonce + ciphertext)
            temporary.flush()
            os.fsync(temporary.fileno())
        except OSError:
            temporary.close()
            temporary_path.unlink()
            raise
    try:
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)

def read_password(prompt: str) -> str:
    # getpass no debe recurrir a una entrada con eco si no hay terminal seguro.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)

        return getpass.getpass(prompt)

def read_required(prompt: str) -> str:
    value = input(prompt).strip()

    if not value:
        raise ValueError("Los campos solicitados no pueden estar vacios.")
    
    return value

def handle_genkeypair(path: Path = DEFAULT_KEYSTORE) -> int:
    """Genera un par RSA y guarda la entrada en un almacen cifrado."""
    try:
        ensure_crypto_available()
        algorithm = resolve_key_algorithm(keyalg)
        resolved_keysize = resolve_key_size(keysize)
        password = read_store_password(path, storepass)
        entries = load_keystore(path, password)
        alias = resolve_alias(alias)

        if alias in entries:
            raise ValueError(f"El alias '{alias}' ya existe.")
        key_password = resolve_key_password(keypass, password, alias)
        dn = resolve_dname(dname)
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=resolved_keysize
        )
        entries[alias] = KeyEntry(
            private_key=private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(key_password.encode("utf-8")),
            ).decode("ascii"),
            public_key=private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii"),
            dn=dn,
        )

        save_keystore(path, password, entries)

    except getpass.GetPassWarning:
        print("Error: no hay un terminal disponible para ocultar la contrasena.", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)

        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nError: operacion cancelada; no se ha guardado la entrada.", file=sys.stderr)

        return 1
    print(
        f"Exito: par {algorithm} de {resolved_keysize} bits guardado con alias '{alias}' en '{path}'."
    )
    return 0

def handle_certreq() -> int:
    """Punto de entrada para la futura generacion de solicitudes CSR."""
    print("Comando --certreq seleccionado.")
    print("La generacion de solicitudes CSR se implementara en el siguiente modulo.")
    return 0


def print_genkeypair_help() -> None:
    print(
        "usage: mykeytool.py -genkeypair -keyalg KEYALG [-keystore KEYSTORE] "
        "[-alias ALIAS] [-dname DNAME] [-storepass STOREPASS] [-keypass KEYPASS] "
        "[-keysize KEYSIZE]",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print("Required for -genkeypair:", file=sys.stderr)
    print("  -keyalg KEYALG    algoritmo de la clave (solo RSA)", file=sys.stderr)
    print("", file=sys.stderr)
    print("Optional for -genkeypair:", file=sys.stderr)
    print("  -keystore KEYSTORE", file=sys.stderr)
    print("  -alias ALIAS", file=sys.stderr)
    print("  -dname DNAME", file=sys.stderr)
    print("  -storepass STOREPASS", file=sys.stderr)
    print("  -keypass KEYPASS", file=sys.stderr)
    print("  -keysize KEYSIZE", file=sys.stderr)


def print_main_help() -> None:
    print("usage: mykeytool.py [command]", file=sys.stdout)
    print("", file=sys.stdout)
    print("Comandos disponibles:", file=sys.stdout)
    print("  -genkeypair, --genkeypair    genera un par de claves", file=sys.stdout)
    print("  -certreq, --certreq          genera una solicitud CSR", file=sys.stdout)
    print("", file=sys.stdout)
    print("Usa 'mykeytool.py -genkeypair -h' para ver sus argumentos.", file=sys.stdout)

def build_parser() -> argparse.ArgumentParser:
    """Construye y devuelve el analizador de argumentos de la aplicacion."""
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description=(
            "Simulador en Python de las funciones esenciales de Java Keytool. "
            "Selecciona una operacion para gestionar el KeyStore."
        ),
        epilog="Ejemplo: python3 mykeytool.py --genkeypair",
    )

    commands = parser.add_mutually_exclusive_group(required=False)
    commands.add_argument(
        "-genkeypair",
        "--genkeypair",
        action="store_const",
        const="genkeypair",
        dest="command",
        help="genera un par de claves RSA y lo guarda en el KeyStore",
    )
    commands.add_argument(
        "-certreq",
        "--certreq",
        action="store_const",
        const="certreq",
        dest="command",
        help="genera una solicitud de firma de certificado (CSR)",
    )
    parser.add_argument(
        "-keystore",
        "--keystore",
        type=Path,
        default=DEFAULT_KEYSTORE,
        help="archivo del almacen propio cifrado (por defecto: keystore.myks)",
    )

    parser.add_argument("-alias", help="alias de la entrada a generar")
    parser.add_argument("-dname", help="DN en formato CN=..., OU=..., O=..., L=..., ST=..., C=...")
    parser.add_argument("-storepass", help="contrasena del KeyStore")
    parser.add_argument("-keypass", help="contrasena de la clave generada")
    parser.add_argument("-keyalg", help="algoritmo de la clave (solo RSA)")
    parser.add_argument("-keysize", type=int, help="tamano de clave en bits")

    return parser

def main(argv: Sequence[str] | None = None) -> int:
    """Procesa los argumentos y ejecuta el manejador del comando elegido."""
    handoff_result = handoff_to_project_venv(argv)

    if handoff_result is not None:
        return handoff_result
    arg_list = list(argv if argv is not None else sys.argv[1:])
    parser = build_parser()
    if any(flag in arg_list for flag in ("-genkeypair", "--genkeypair")) and any(
        flag in arg_list for flag in ("-h", "--help")
    ):
        print_genkeypair_help()
        return 0

    args = parser.parse_args(arg_list)

    if args.command is None and not any(flag in arg_list for flag in ("-h", "--help")):
        print_main_help()
        return 0

    if args.command is None:
        print_main_help()
        return 0

    handlers: dict[str, CommandHandler] = {
        "genkeypair": lambda: handle_genkeypair(
            args.keystore,
            alias=args.alias,
            storepass=args.storepass,
            keypass=args.keypass,
            dname=args.dname,
            keyalg=args.keyalg,
            keysize=args.keysize,
        ),

        "certreq": handle_certreq,
    }

    return handlers[args.command]()

if __name__ == "__main__":
    raise SystemExit(main())