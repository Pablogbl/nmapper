"""Tests de nmapper. Ejecutar con:  python3 -m unittest discover tests"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nmapper  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


class TestParsing(unittest.TestCase):
    def test_xml_detecta_puertos_abiertos(self):
        ports = nmapper.parse(load("scan.xml"))
        abiertos = [p for p in ports if p.state == "open"]
        self.assertEqual(len(abiertos), 2)
        self.assertEqual({p.port for p in abiertos}, {22, 80})

    def test_xml_ignora_cerrados_en_la_tabla(self):
        ports = nmapper.parse(load("scan.xml"))
        tabla = nmapper.render_table(ports)
        self.assertNotIn("443", tabla)  # el 443 está closed

    def test_texto_equivale_al_xml(self):
        del_xml = {p.port for p in nmapper.parse(load("scan.xml")) if p.state == "open"}
        del_txt = {p.port for p in nmapper.parse(load("scan.txt")) if p.state == "open"}
        self.assertEqual(del_xml, del_txt)

    def test_version_con_espacios_no_se_parte(self):
        ports = nmapper.parse(load("scan.txt"))
        ssh = next(p for p in ports if p.port == 22)
        self.assertIn("OpenSSH 8.9p1", ssh.version)

    def test_deteccion_de_formato(self):
        self.assertEqual(len(nmapper.parse("<?xml version='1.0'?><nmaprun></nmaprun>")), 0)


class TestRender(unittest.TestCase):
    def setUp(self):
        self.ports = nmapper.parse(load("scan.xml"))

    def test_tabla_es_markdown_valido(self):
        tabla = nmapper.render_table(self.ports)
        self.assertTrue(tabla.startswith("| Puerto |"))
        self.assertIn("|---|", tabla)

    def test_linea_de_puertos(self):
        self.assertEqual(nmapper.render_ports_line(self.ports), "22,80")

    def test_resumen_menciona_el_conteo(self):
        resumen = nmapper.render_summary(self.ports)
        self.assertIn("2 puertos abiertos", resumen)

    def test_sin_puertos_no_revienta(self):
        self.assertIn("No se detectaron", nmapper.render_table([]))
        self.assertIn("no reveló", nmapper.render_summary([]))


class TestSingular(unittest.TestCase):
    def test_un_solo_puerto_usa_singular(self):
        un_puerto = [nmapper.Port(80, "tcp", "open", "http", "nginx")]
        resumen = nmapper.render_summary(un_puerto)
        self.assertIn("1 puerto abierto", resumen)
        self.assertIn("el puerto **80**", resumen)


if __name__ == "__main__":
    unittest.main(verbosity=2)
