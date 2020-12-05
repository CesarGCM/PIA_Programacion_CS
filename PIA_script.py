from email.mime.multipart import MIMEMultipart
from virustotal_python import Virustotal
from PIL.ExifTags import TAGS, GPSTAGS
from cryptography.fernet import Fernet
from email.mime.text import MIMEText
from base64 import urlsafe_b64encode
from bs4 import BeautifulSoup
from datetime import datetime
from PIL import Image
import subprocess
import argparse
import requests
import smtplib
import logging
import random
import string
import socket
import json
import os


def scan_url(url_scan, api_key):
    vtotal = Virustotal(API_KEY=api_key,
                        API_VERSION="v3")
    try:
        resp = vtotal.request("urls", data={"url": url_scan}, method="POST")
        url_id = urlsafe_b64encode(url_scan.encode()).decode().strip("=")
        analysis_resp = vtotal.request(f"urls/{url_id}")
        results = analysis_resp.data
        if results['attributes']['last_analysis_stats']['malicious'] != 0:
            logging.info("La pagina contiene %s agentes maliciosos.\n"
                         "No se descargará la pagina" % results['attributes']['last_analysis_stats']['malicious'])
            scan_value = True
            return scan_value
        else:
            logging.info('"---La pagina esta libre de amenazas---')

    except Exception as err:
        logging.info(f"An error occurred: {err}\nCatching and continuing with program.")


def search_headers(headers):
    try:
        logging.info("Servidor: %s" % headers['Server'])
        logging.info("Fecha y hora: %s\n" % headers['Date'])
    except Exception as error_headers:
        logging.info("No se pudieron detectar los headers")
        logging.error("Error: %s" % error_headers)


def send_mails():
    data = {}
    try:
        with open('./data.json') as f:
            data = json.load(f)
    except Exception as error_file:
        logging.info("No se encontro el archivo")
        logging.error("Error: %s" % error_file)
    msg = MIMEMultipart()
    message = ''
    for i in open('Errors_Report.log', 'r'):
        message += str(i)

    msg['From'] = data['user']
    msg['To'] = data['addressee']
    msg['Subject'] = "Reporte de Errores" + str(datetime.now())
    msg.attach(MIMEText(message, 'plain'))

    server = smtplib.SMTP(data['server'])
    server.starttls()
    server.login(data['user'], data['pass'])
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()


def password():
    key_cesar = ''
    for i in range(10):
        key_cesar += str(random.choice(string.ascii_letters))
    file = open('key_client.txt', 'w')
    file.write(key_cesar)
    file.close()
    return key_cesar


def encoder(message, f_key):
    symbols = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'
    spaces = 1

    while spaces > 0:
        spaces = f_key.count(' ')
        if f_key.isalpha() is False:
            spaces += 1
    key_encoder = len(f_key)

    translated = ''

    for symbol in message:
        if symbol in symbols:
            symbol_index = symbols.find(symbol)
            translated_index = symbol_index + key_encoder

            if translated_index >= len(symbols):
                translated_index = translated_index - len(symbols)
            elif translated_index < 0:
                translated_index = translated_index + len(symbols)

            translated = translated + symbols[translated_index]
        else:
            translated = translated + symbol

    return translated


def img_downloader(img_soup):
    counter = 1
    for links_from_soup in img_soup.find_all('img'):
        try:
            url_image = "https:" + links_from_soup.get('src')
            image_local_name = "./img_downloads/img_" + str(counter) + ".jpg"
            image = requests.get(url_image).content
            with open(image_local_name, 'wb') as handler:
                handler.write(image)
        except Exception:
            try:
                url_image = links_from_soup.get('src')
                image_local_name = "./img_downloads/img_" + str(counter) + ".jpg"
                image = requests.get(url_image).content
                with open(image_local_name, 'wb') as handler:
                    handler.write(image)
            except Exception as error_download:
                url_image = links_from_soup.get('src')
                logging.info("url de imagen : https:" + url_image + " no valido")
                logging.error("Error: %s\n" % error_download)
                value_validator = True
                return value_validator

        counter += 1


def decode_gps_info(exif):
    gpsinfo = {}
    if 'GPSInfo' in exif:
        Nsec = exif['GPSInfo'][2][2]
        Nmin = exif['GPSInfo'][2][1]
        Ndeg = exif['GPSInfo'][2][0]
        Wsec = exif['GPSInfo'][4][2]
        Wmin = exif['GPSInfo'][4][1]
        Wdeg = exif['GPSInfo'][4][0]
        if exif['GPSInfo'][1] == 'N':
            Nmult = 1
        else:
            Nmult = -1
        if exif['GPSInfo'][3] == 'E':
            Wmult = 1
        else:
            Wmult = -1
        Lat = Nmult * (Ndeg + (Nmin + Nsec / 60.0) / 60.0)
        Lng = Wmult * (Wdeg + (Wmin + Wsec / 60.0) / 60.0)
        exif['GPSInfo'] = {"Lat": Lat, "Lng": Lng}


def get_exif_metadata(image_path):
    ret = {}
    image = Image.open(image_path)
    if hasattr(image, '_getexif'):
        exifinfo = image._getexif()
        if exifinfo is not None:
            for tag, value in exifinfo.items():
                decoded = TAGS.get(tag, tag)
                ret[decoded] = value
    decode_gps_info(ret)
    return ret


def print_meta(f_key):
    directory = os.getcwd()
    os.chdir(directory + "/img_downloads")
    try:
        os.mkdir("./img_metadata")
    except:
        pass
    counter = 1
    for root, dirs, files in os.walk(".", topdown=False):
        for name in files:
            file = open("./img_metadata/metadata_img_" + str(counter) + ".txt", "w")
            file.write("[+] Metadata for file: %s " % name + os.linesep)
            try:
                exif_data = {}
                exif = get_exif_metadata(name)
                for metadata in exif:
                    line_text = "Metadata: %s - Value: %s " % (metadata, exif[metadata])
                    file.write(encoder(line_text, f_key) + os.linesep)
                counter += 1
            except Exception as error_image:
                logging.info("imagen: %s [Formato no detectado]" % name)
                logging.error("Error: %s\n" % error_image)
                value_validator = True
                return value_validator
            file.close()


def tcp_connection(mensaje):
    clave = Fernet.generate_key()
    cipher_suite = Fernet(clave)

    file = open('C:/tcp_key.key', 'wb')
    file.write(clave)
    file.close()

    mensaje_bytes = mensaje.encode()
    msj_cifrado = cipher_suite.encrypt(mensaje_bytes)

    TCP_IP = '127.0.0.1'
    TCP_PORT = 5000
    BUFFER_SIZE = 2048

    s_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_object.connect((TCP_IP, TCP_PORT))
    s_object.send(msj_cifrado)
    respuesta = s_object.recv(BUFFER_SIZE).decode()
    s_object.close()

    return respuesta


desc = '"Modo de uso: PIA_script.py -url "pagina a escanear"'
parser = argparse.ArgumentParser(description='PIA_script', epilog=desc,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-url", metavar='URL', dest="url",
                    help="Url de la pagina a descargar (todas las imagenes)", required=True)
parser.add_argument("-api", metavar='API KEY', dest="api",
                    help="Api_key necesaria para el escaneo (https://www.virustotal.com/gui/)", required=True)
parameters = parser.parse_args()

logging.basicConfig(filename='Errors_Report.log', level=logging.INFO)


if __name__ == '__main__':
    key = password()
    key_validator = tcp_connection(key)

    value = True
    value_scan = False
    url = parameters.url
    api_key = parameters.api
    value_scan = scan_url(url, api_key)

    if value_scan is not True:
        try:
            link = requests.get(url)  # "http://www.lagartopedia.com/dragon-de-komodo/"
            logging.info("Url: %s -Status code: %s\n" % (url, str(link.status_code)))
        except Exception as error:
            value = False
            logging.info('El url ingresado no existe')
            logging.error('Error: %s \n' % error)
            error_value = True

        if value is True:
            if link.status_code == 200:

                try:
                    os.mkdir("./img_downloads")
                except Exception:
                    pass

                search_headers(link.headers)
                soup = BeautifulSoup(link.text, 'html.parser')
                error_value = img_downloader(soup)
                error_value = print_meta(key)
                os.chdir("..")
            else:
                logging.info("Error: La pagina no permite descargar archivos. Status:  %s\n" % str(link.status_code))

        if error_value is not True:
            logging.info(
                "---No se generaron errores---"
            )

        if key_validator != "Entregado":
            logging.info("El servidor no recibió la clave")

        send_mails()

    subprocess.Popen([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                      '-ExecutionPolicy',
                      'Unrestricted',
                      './hash_ps.ps1'])

