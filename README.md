### Patrones Phishing
---

*Detecta patrones comunes en correos de phishing y genera expresiones regulares (regex) para bloquear futuros ataques.*

Ideal para analistas de seguridad, equipos SOC o entusiastas que quieren automatizar la detección de phishing mediante análisis de texto.


## Características

- 📥 Lee múltiples correos de phishing desde archivos `.txt`.
- 🔍 Extrae **n-gramas** (secuencias de 2 a 5 palabras) frecuentes.
- 🧹 Normaliza texto: elimina URLs, emails, números largos y puntuación.
- 🧮 Filtra patrones por frecuencia mínima configurable.
- 🧩 Genera **expresiones regulares listas para usar** en filtros de correo, SIEM, WAF, etc.
- 💾 Exporta resultados en `JSON` con patrones y sus regex correspondientes.
- 🖥️ Soporta argumentos por línea de comandos: rutas, umbrales, tamaños de n-gramas.

---

## Requisitos

- Python 3.7 o superior

---

## Instalación

Clona el repositorio:

```bash
git clone https://github.com/Sadino07/patrones_phishing.git
cd patrones_phishing
```

---

## Uso Básico

Coloca tus correos de phishing en formato `.txt` dentro de la carpeta `emails/`.

Ejecuta el detector:

```bash
python patrones_phishing.py
```

Por defecto:
- Busca en `emails/`
- Usa umbral de frecuencia = 2
- Busca n-gramas de 2 a 5 palabras
- Guarda salida en `patrones_phishing.json`

---

## Uso Avanzado (Argumentos)

```bash
python patrones_phishing.py --carpeta ./mis_emails --umbral 3 --min_n 3 --max_n 6 --salida output.json
```

### Argumentos disponibles:

| Argumento       | Descripción                                      | Valor por defecto     |
|-----------------|--------------------------------------------------|------------------------|
| `--carpeta`     | Carpeta con archivos `.txt` de emails           | `emails/`             |
| `--umbral`      | Frecuencia mínima para considerar un patrón     | `2`                   |
| `--min_n`       | Tamaño mínimo de n-grama (palabras)             | `2`                   |
| `--max_n`       | Tamaño máximo de n-grama (palabras)             | `5`                   |
| `--salida`      | Archivo de salida JSON                          | `patrones_phishing.json` |

---

## Ejemplo de Salida (`patrones_phishing.json`)

```json
{
  "patrones": {
    "haga clic aquí": 8,
    "para verificar su cuenta": 6,
    "no ignore este mensaje": 5
  },
  "regex_sugeridas": [
    ".*haga\\s+clic\\s+aquí.*",
    ".*para\\s+verificar\\s+su\\s+cuenta.*",
    ".*no\\s+ignore\\s+este\\s+mensaje.*"
  ]
}
```

Estas regex pueden usarse directamente en:
- Filtros de correo (Postfix, Exchange, Gmail API)
- SIEM (Splunk, QRadar, Elastic)
- WAF o reglas de NIDS