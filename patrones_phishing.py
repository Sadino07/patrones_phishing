import os
import re
import json
import glob
import logging
from collections import Counter
import argparse

# Configuración básica
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def normalizar_texto(texto):
    texto = texto.lower()
    texto = re.sub(r'https?://\S+', 'URL', texto)
    texto = re.sub(r'\S+@\S+', 'EMAIL', texto)
    texto = re.sub(r'\b\d{5,}\b', 'NUMERO', texto)
    texto = re.sub(r'[^\w\s]', ' ', texto)
    texto = re.sub(r'\s+', ' ', texto).strip()
    return texto

def extraer_ngramas(texto, min_n=2, max_n=5):
    palabras = texto.split()
    ngramas = []
    for n in range(min_n, max_n + 1):
        for i in range(len(palabras) - n + 1):
            ngrama = " ".join(palabras[i:i+n])
            ngramas.append(ngrama)
    return ngramas

def leer_emails(carpeta):
    emails = []
    ruta_patron = os.path.join(carpeta, "*.txt")
    archivos = glob.glob(ruta_patron)
    if not archivos:
        logging.warning(f"No se encontraron archivos .txt en {carpeta}")
        return emails
    for archivo in archivos:
        try:
            with open(archivo, "r", encoding="utf-8", errors="ignore") as f:
                contenido = f.read()
                emails.append(normalizar_texto(contenido))
                logging.info(f"Leído: {archivo}")
        except Exception as e:
            logging.error(f"Error leyendo {archivo}: {e}")
    return emails

def encontrar_patrones_repetidos(emails, umbral=2, min_n=2, max_n=5):
    todos_ngramas = []
    for email in emails:
        ngramas = extraer_ngramas(email, min_n, max_n)
        todos_ngramas.extend(ngramas)

    contador = Counter(todos_ngramas)
    patrones_frecuentes = {ngrama: freq for ngrama, freq in contador.items() if freq >= umbral}
    
    # Ordenar por frecuencia descendente
    patrones_ordenados = dict(sorted(patrones_frecuentes.items(), key=lambda x: x[1], reverse=True))
    return patrones_ordenados

def generar_regex_patrones(patrones_dict):
    regex_list = []
    for patron in patrones_dict.keys():
        patron_regex = re.escape(patron)
        patron_regex = re.sub(r'\\ ', r'\\s+', patron_regex)  # Permitir múltiples espacios
        regex_list.append(f".*{patron_regex}.*")
    return regex_list

def guardar_patrones(patrones_con_frecuencia, archivo_salida="patrones_phishing.json"):
    salida = {
        "patrones": patrones_con_frecuencia,
        "regex_sugeridas": generar_regex_patrones(patrones_con_frecuencia)
    }
    with open(archivo_salida, "w", encoding="utf-8") as f:
        json.dump(salida, f, indent=4, ensure_ascii=False)
    logging.info(f"Patrones y regex guardados en {archivo_salida}")

def main():
    parser = argparse.ArgumentParser(description="Detecta patrones en emails de phishing para generar regex de bloqueo.")
    parser.add_argument("--carpeta", default="emails/", help="Carpeta con archivos .txt de emails")
    parser.add_argument("--umbral", type=int, default=2, help="Frecuencia mínima para considerar un patrón")
    parser.add_argument("--min_n", type=int, default=2, help="Tamaño mínimo de n-grama")
    parser.add_argument("--max_n", type=int, default=5, help="Tamaño máximo de n-grama")
    parser.add_argument("--salida", default="patrones_phishing.json", help="Archivo de salida JSON")
    args = parser.parse_args()

    logging.info("Leyendo emails...")
    emails = leer_emails(args.carpeta)
    if not emails:
        logging.error("No se cargaron emails. Saliendo.")
        return

    logging.info("Extrayendo patrones...")
    patrones = encontrar_patrones_repetidos(emails, args.umbral, args.min_n, args.max_n)

    if patrones:
        logging.info(f"Se encontraron {len(patrones)} patrones con frecuencia >= {args.umbral}")
        for patron, freq in list(patrones.items())[:10]:  # Mostrar top 10
            print(f"'{patron}' → {freq} veces")
    else:
        logging.warning("No se encontraron patrones repetidos.")

    guardar_patrones(patrones, args.salida)

if __name__ == "__main__":
    main()