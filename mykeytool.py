"""Interfaz de linea de comandos para el simulador de Java Keytool."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence


CommandHandler = Callable[[], int]


def handle_genkeypair() -> int:
    """Punto de entrada para la futura generacion de pares de claves."""
    print("Comando --genkeypair seleccionado.")
    print("La generacion de claves se implementara en el siguiente modulo.")
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

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Procesa los argumentos y ejecuta el manejador del comando elegido."""
    parser = build_parser()
    args = parser.parse_args(argv)

    handlers: dict[str, CommandHandler] = {
        "genkeypair": handle_genkeypair,
        "certreq": handle_certreq,
    }
    return handlers[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())

