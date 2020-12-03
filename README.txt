Name: PIA_programacion_cs
Author name(s): Cesar Giovani, Johan Uvalle, Karla Rodr
Release date: 8/11/20
Language: Es
GitHub repository: "Link"


-------------------------------------------------------

---Instrucciones de uso:---

*Asegurese de revisar el archivo requirements.txt e instalar todos los modulos necesarios antes de la ejecuci�n*

-Iniciar Servidor TCP ['TCPserver.py']

-Iniciar Cliente TCP con los parametros -url "dirrecion web" -api "clave api (Virustotal.com)" ['./PIA_script.py -url "link" -api "api key"']

*Notas
 ./PIA_script.py acepta los siguientes parametros:
	[-h] seccion de ayuda
	[-url] link a escanear
	[-api] clave de api para escanear amenazas
	Conseguir api key en: https://www.virustotal.com/gui/

 Los modulos "PIA_script.py" y "hash_ps.ps1" deben estar en la misma direcci�n. "TCPserver.py" puede estar en cualquier direcci�n.

-------------------------------------------------------

---Modulos---

(hash_ps.ps1):
Script de powershell que almacena los hash en el archivo hash.txt (se activa automaticamente por "PIA_script.py")


-PIA_script.py:
Almacena la mayor cantidad de funciones del proyecto, funciona como cliente en la conexi�n TCP, genera la carpeta de imagenes, metadatas, claves tcp y cliente y reporte de errores.


-TCPserver.py:
Funciona como servidor en la conexi�n TCP, almacena la clave enviada por el cliente y regresa una respuesta de confirmaci�n.

-------------------------------------------------------

---Recursos---

*Archivos [.json]

-data: Almacena los datos necesarios para el envio de el correo [modificarlo antes de usar]

*Archivos [.txt]

-requirements: Texto con los datos de los modulos necesarios para una correcta ejecuci�n

--------------------------------------------------------

---Archivos generados---

*Archivos [.txt]

-key_client: Texto con la clave de cifrado almacenado para el cliente

-key_server: Texto con la clave de cifrado almacenado para el servidor (se almacenar� en la misma ubicaci�n que TCPserver.py)

-hash: Texto con el hash de todos los archivos y modulos existentes y archivos generados por los scripts.

*Archivos [.key]

-tcp_key: Archivo .key que almacena la clave para la conexxi�n TCP cliente-servidor (se almacenar� en la ubicaci�n "C:\")

*Archivos [.log]

-Errors_Report: archivo log con los datos de los errores generados por los modulos

*Archivos [folders]

img_downloads: carpeta con las imagenes descargadas (contiene la sub-carpeta con los textos con las metadatas codificadas extra�das de las imagenes)