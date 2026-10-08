"""Interfaz de linea de comandos para el simulador de Java Keytool."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
import warnings
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TypedDict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


CommandHandler = Callable[[], int]
DEFAULT_KEYSTORE = Path("keystore.myks")
STORE_HEADER = b"MYKEYSTORE\x01"
DN_FIELDS = ("CN", "OU", "O", "L", "ST", "C")


class KeyEntry(TypedDict):
    private_key: str
    public_key: str
    dn: dict[str, str]


def derive_store_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(
        password.encode("utf-8")
    )


def load_keystore(path: Path, password: str) -> dict[str, KeyEntry]:
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
        password = read_password("Contrasena del KeyStore: ")
        if not password:
            raise ValueError("La contrasena no puede estar vacia.")
        is_new = not path.exists()
        if is_new:
            if len(password) < 8:
                raise ValueError("La contrasena debe tener al menos 8 caracteres.")
            if read_password("Confirma la contrasena: ") != password:
                raise ValueError("Las contrasenas no coinciden.")
        entries = load_keystore(path, password)
        alias = read_required("Alias unico: ")
        if alias in entries:
            raise ValueError(f"El alias '{alias}' ya existe.")
        dn = {field: read_required(f"{field}: ") for field in DN_FIELDS}
        country = dn["C"]
        if len(country) != 2 or not country.isascii() or not country.isalpha():
            raise ValueError("C debe ser un codigo de pais de dos letras (p. ej. ES).")
        dn["C"] = country.upper()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        entries[alias] = KeyEntry(
            private_key=private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
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
    print(f"Exito: par RSA de 2048 bits guardado con alias '{alias}' en '{path}'.")
    return 0


def handle_certreq() -> int:
    """Punto de entrada para la futura generacion de solicitudes CSR."""
    print("Comando --certreq seleccionado.")
    print("La generacion de solicitudes CSR se implementara en el siguiente modulo.")
    return 0


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

    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument(
        "--genkeypair",
        action="store_const",
        const="genkeypair",
        dest="command",
        help="genera un par de claves RSA y lo guarda en el KeyStore",
    )
    commands.add_argument(
        "--certreq",
        action="store_const",
        const="certreq",
        dest="command",
        help="genera una solicitud de firma de certificado (CSR)",
    )
    parser.add_argument(
        "--keystore",
        type=Path,
        default=DEFAULT_KEYSTORE,
        help="archivo del almacen propio cifrado (por defecto: keystore.myks)",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Procesa los argumentos y ejecuta el manejador del comando elegido."""
    parser = build_parser()
    args = parser.parse_args(argv)

    handlers: dict[str, CommandHandler] = {
        "genkeypair": lambda: handle_genkeypair(args.keystore),
        "certreq": handle_certreq,
    }
    return handlers[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
