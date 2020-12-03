from cryptography.fernet import Fernet
import socket



TCP_IP = '127.0.0.1'
TCP_PORT = 5000
BUFFER_SIZE = 2048

s_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_object.bind((TCP_IP, TCP_PORT))
s_object.listen(1)
(conn, addr) = s_object.accept()
print('Dirección de la conexión: ', addr)
while True:
    msj_cifrado = conn.recv(BUFFER_SIZE)
    conn.send(b"Entregado")
    break
conn.close()

file = open('C:/tcp_key.key', 'rb')
clave = file.read()
file.close()
cipher_suite = Fernet(clave)

mensajeBytes = cipher_suite.decrypt(msj_cifrado, None)
mensaje = mensajeBytes.decode()
file = open("./key_server.txt", "w")
file.write(mensaje)
file.close()
