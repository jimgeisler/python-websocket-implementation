# -*- coding: <utf-8> -*-

import struct
import string

try:
    from hashlib import md5
except ImportError: #pragma NO COVER
    from md5 import md5

def getHeaderValue(request, header):
    """ Returns the value of a header specified header field. """
    delim = ': '
    header_plus_delim = header.strip() + delim
    start = request.index(header_plus_delim)
    end = request.index('\r\n', start)
    return request[start+len(header)+len(delim):end]

def extract_number(value):
    """
    Utility function which, given a string like 'g98sd  5[]221@1', will
    return 9852211. Used to parse the Sec-WebSocket-Key headers.
    """
    out = ""
    spaces = 0
    for char in value:
        if char in string.digits:
            out += char
        elif char == " ":
            spaces += 1
    return int(out) / spaces

def handshakeIt(s):
    """
    Creates the appropriate response, calculating the necessary
    websocket 76 protocol challenge.
    """
    request = s.recv(1024)
    
    print(request)
    
    origin = getHeaderValue(request, "Origin").lower()
    host_url = getHeaderValue(request, "Host")
    location = "ws://" + host_url + "/"

    subprotocol = '*'

    key_1 = extract_number(getHeaderValue(request, 'Sec-WebSocket-Key1'))
    key_2 = extract_number(getHeaderValue(request, 'Sec-WebSocket-Key2'))
    key_3 = request[-8:]
    
    key = struct.pack(">II", key_1, key_2) + key_3
    response = md5(key).digest()

    handshake_reply = ("HTTP/1.1 101 WebSocket Protocol Handshake\r\n"
                       "Upgrade: WebSocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Origin: %s\r\n"
                       "Sec-WebSocket-Protocol: %s\r\n"
                       "Sec-WebSocket-Location: %s\r\n"
                       "\r\n%s"% (
            origin,
            subprotocol,
            location,
            response))
    s.sendall(handshake_reply)
