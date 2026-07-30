#!/usr/bin/env python3
"""
nmapper — convierte la salida de nmap en la tabla de puertos y el resumen
en prosa que se usan en un writeup de pentesting.

Acepta dos formatos de entrada:
  * XML de nmap (generado con `nmap -oX fichero.xml ...`) — el más fiable.
  * Salida de texto normal (la que imprime nmap por pantalla).

El formato se detecta solo. Uso típico:

    nmap -p- -sVC 10.10.10.10 -oX scan.xml
    python3 nmapper.py scan.xml

o directamente desde una tubería:

    nmap -sVC 10.10.10.10 | python3 nmapper.py -
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class Port:
    port: int
    protocol: str
    state: str
    service: str
    version: str

    @property
    def full_service(self) -> str:
        """Nombre de servicio + versión, tal como iría en la tabla."""
        return f"{self.service} {self.version}".strip() if self.version else self.service


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #

def parse_xml(text: str) -> list[Port]:
    """Extrae los puertos de la salida XML de nmap (-oX)."""
    root = ET.fromstring(text)
    ports: list[Port] = []

    for port_el in root.iter("port"):
        state_el = port_el.find("state")
        state = state_el.get("state", "") if state_el is not None else ""

        service_el = port_el.find("service")
        service = version = ""
        if service_el is not None:
            service = service_el.get("name", "")
            version = " ".join(
                filter(None, [
                    service_el.get("product", ""),
                    service_el.get("version", ""),
                    service_el.get("extrainfo", ""),
                ])
            ).strip()

        ports.append(Port(
            port=int(port_el.get("portid", 0)),
            protocol=port_el.get("protocol", "tcp"),
            state=state,
            service=service,
            version=version,
        ))

    return ports


# Línea tipo:  22/tcp   open   ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
TEXT_LINE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
    r"(?P<state>\w+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<version>.+?))?\s*$"
)


def parse_text(text: str) -> list[Port]:
    """Extrae los puertos de la salida de texto normal de nmap."""
    ports: list[Port] = []
    for line in text.splitlines():
        m = TEXT_LINE.match(line.strip())
        if not m:
            continue
        ports.append(Port(
            port=int(m.group("port")),
            protocol=m.group("proto"),
            state=m.group("state"),
            service=m.group("service"),
            version=(m.group("version") or "").strip(),
        ))
    return ports


def parse(text: str) -> list[Port]:
    """Detecta el formato y delega en el parser adecuado."""
    stripped = text.lstrip()
    if stripped.startswith("<?xml") or stripped.startswith("<nmaprun"):
        return parse_xml(text)
    return parse_text(text)


# --------------------------------------------------------------------------- #
# Salida
# --------------------------------------------------------------------------- #

def render_table(ports: list[Port]) -> str:
    """Tabla Markdown de los puertos abiertos."""
    openp = [p for p in ports if p.state == "open"]
    if not openp:
        return "_No se detectaron puertos abiertos._"

    rows = ["| Puerto | Servicio | Versión |", "|---|---|---|"]
    for p in sorted(openp, key=lambda x: x.port):
        rows.append(f"| {p.port}/{p.protocol} | {p.service or '—'} | {p.version or '—'} |")
    return "\n".join(rows)


def render_summary(ports: list[Port]) -> str:
    """Frase de resumen en español para el writeup."""
    openp = sorted((p for p in ports if p.state == "open"), key=lambda x: x.port)
    if not openp:
        return "El escaneo no reveló puertos abiertos."

    nums = [str(p.port) for p in openp]
    if len(nums) == 1:
        listado = f"el puerto **{nums[0]}**"
    else:
        listado = "los puertos " + ", ".join(f"**{n}**" for n in nums[:-1]) + f" y **{nums[-1]}**"

    servicios = ", ".join(
        f"`{p.port}` ({p.full_service})" for p in openp
    )
    return (
        f"El escaneo revela {len(openp)} "
        f"{'puerto abierto' if len(openp) == 1 else 'puertos abiertos'}: {listado}. "
        f"Servicios detectados: {servicios}."
    )


def render_ports_line(ports: list[Port]) -> str:
    """Lista de puertos separada por comas, útil para el segundo escaneo dirigido."""
    openp = sorted((p for p in ports if p.state == "open"), key=lambda x: x.port)
    return ",".join(str(p.port) for p in openp)


# --------------------------------------------------------------------------- #

def read_input(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    with open(source, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="nmapper",
        description="Convierte la salida de nmap en la tabla y el resumen de un writeup.",
    )
    parser.add_argument(
        "input",
        help="fichero de nmap (XML de -oX o texto), o '-' para leer de stdin",
    )
    parser.add_argument(
        "--only",
        choices=["table", "summary", "ports"],
        help="mostrar solo una sección (por defecto: todas)",
    )
    args = parser.parse_args()

    try:
        raw = read_input(args.input)
    except FileNotFoundError:
        print(f"[!] No se encuentra el fichero: {args.input}", file=sys.stderr)
        return 1

    try:
        ports = parse(raw)
    except ET.ParseError as exc:
        print(f"[!] XML mal formado: {exc}", file=sys.stderr)
        return 1

    if not ports:
        print("[!] No se ha reconocido ningún puerto en la entrada.", file=sys.stderr)
        return 1

    if args.only == "table":
        print(render_table(ports))
    elif args.only == "summary":
        print(render_summary(ports))
    elif args.only == "ports":
        print(render_ports_line(ports))
    else:
        print("## Enumeración de puertos\n")
        print(render_summary(ports))
        print()
        print(render_table(ports))

    return 0


if __name__ == "__main__":
    sys.exit(main())
