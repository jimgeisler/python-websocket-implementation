import socket
import sys  
from handshaking import handshakeIt

port = 8010

def handle(client, address):
    data = ''
    handshakeIt(client)
    while True:
        tmp = client.recv(128)  
        data += tmp;  

        validated = []  

        msgs = data.split('\xff')  
        data = msgs.pop()  

        for msg in msgs:  
            if msg[0] == '\x00':  
                validated.append(msg[1:])  

        for v in validated:  
            print(v)  
            client.send('\x00' + v + '\xff')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  

sock.bind(("", port))  
sock.listen(1)  
  
print("Server waiting for websocket clients on %s", port)

try:
    client, address = sock.accept()  
    handle(client, address)
                    
except KeyboardInterrupt:
    try:
        #sock.shutdown(2)
        print('\nsocket shutdown')
        sock.close()
        print('socket closed')
    except:
        print('\nsocket never opened')
