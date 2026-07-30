# nmapper

Convierte la salida de `nmap` en la tabla de puertos y el resumen en prosa que uso al documentar una máquina, para no reescribirlos a mano en cada writeup.

Le pasas un escaneo y devuelve tres cosas:

- una **tabla Markdown** de puertos abiertos (`Puerto | Servicio | Versión`),
- una **frase de resumen en español** lista para pegar en el writeup,
- la **lista de puertos** separada por comas, para lanzar el segundo escaneo dirigido.

Sin dependencias externas. Solo Python 3.9+ y la librería estándar.

---

## Uso

Lo más fiable es escanear a XML y pasárselo:

```bash
nmap -p- -sVC 10.10.10.10 -oX scan.xml
python3 nmapper.py scan.xml
```

También lee la salida de texto normal, por si ya tienes el escaneo guardado o quieres encadenarlo por tubería:

```bash
nmap -sVC 10.10.10.10 | python3 nmapper.py -
```

El formato (XML o texto) se detecta solo.

### Salida

```
## Enumeración de puertos

El escaneo revela 2 puertos abiertos: los puertos **22** y **80**.
Servicios detectados: `22` (ssh OpenSSH 8.9p1), `80` (http Werkzeug httpd 2.0.3).

| Puerto | Servicio | Versión |
|---|---|---|
| 22/tcp | ssh | OpenSSH 8.9p1 |
| 80/tcp | http | Werkzeug httpd 2.0.3 |
```

### Secciones sueltas

```bash
python3 nmapper.py scan.xml --only table     # solo la tabla
python3 nmapper.py scan.xml --only summary   # solo el resumen
python3 nmapper.py scan.xml --only ports     # 22,80
```

El flujo típico en una máquina: escaneo completo de puertos, sacas la lista con `--only ports`, y lanzas el escaneo de versiones solo sobre esos:

```bash
nmap -p- 10.10.10.10 -oX all.xml
nmap -p$(python3 nmapper.py all.xml --only ports) -sVC 10.10.10.10 -oX scan.xml
python3 nmapper.py scan.xml
```

---

## Por qué XML y no texto

El formato de texto de nmap está pensado para leerse, no para parsearse: las columnas se alinean con espacios y una versión con paréntesis o espacios puede romper un parser ingenuo. El XML de `-oX` es estable y estructurado, así que es el camino recomendado. El parser de texto está como comodín para escaneos que ya tienes en formato plano.

---

## Tests

```bash
python3 -m unittest discover tests -v
```

---

## Licencia

MIT.
