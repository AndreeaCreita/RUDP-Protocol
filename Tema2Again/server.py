import socket
import sys
import random
import struct



try:
    server= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 55555))
    server.settimeout(50)
    print("Server started")
except socket.error as err:
    print(f"Error. Reason {str(err)}")
    sys.exit()
  
    
FLAGS = {
    "SYN" : (1 << 7),
    "SEQ" : (1 << 6),
    "ACK" : (1 << 5),
    "PSH" : (1 << 4),
    "FIN" : (1 << 3)
}

def extractHeader(data):
    # H = unsigned short B = unsigned char
    seq, ack, flags = struct.unpack('HHB', data[:5])
    flag = {}
    for flagName, flagVal in FLAGS.items():
        flag[flagName] = 1 if (flags & flagVal) else 0
   
    return (seq, ack, flag)

def addHeader(seq, ack, flags, data):
    flagBits = 0
    for flagName in flags:
        flagBits |= FLAGS[flagName]
    return struct.pack('HHB', seq, ack, flagBits) + data.encode()

    
while True:
    # astept syn
    try:
        data, clientAdress = server.recvfrom(100)
        header = extractHeader(data)
        if not header[2]['SYN']:
            continue
        print(f"Primit [seq:{header[0]} ack:{header[1]} flags:{[k for k,v  in header[2].items() if v]}]")
    except socket.timeout:
        # nu am primit syn
        continue

    # generez nr random pt serverSeq
    serverSeq = random.randint(0,10000)
    clientSeq = header[0]
    serverAck = clientSeq + 1

    # trimit syn/ack
    response = addHeader(seq=serverSeq, ack=serverAck, flags=['SYN','ACK'], data='')
    server.sendto(response, clientAdress)
    print(f"Trimit [seq:{serverSeq} ack:{serverAck} flags:{['SYN','ACK']}]")
    break


# astept ACK, daca nu retrimit SYN/ACK
while True:    
    try:
        # astept ACK
        data, clientAdress = server.recvfrom(100)
        header = extractHeader(data)
        if not header[2]['ACK']:
            continue
        
        print(f"Primit [seq:{header[0]} ack:{header[1]} flags:{[k for k,v  in header[2].items() if v]}]")
        clientAck = header[1]
        serverSeq = clientAck
        break
        # gata handshake
    except socket.timeout:
        # nu am primit ack, retrimit syn/ack
        response = addHeader(seq=serverSeq, ack=serverAck, flags=['SYN','ACK'], data='')
        server.sendto(response, clientAdress)
        print(f"Trimit [seq:{serverSeq} ack:{serverAck} flags:['SYN','ACK']]")
        continue

print(" --- ")

# primesc mesaje si trimit ACK
mesajePrimite = set()
while True:
    try:
        # astept mesaj cu PSH
        data, clientAdress = server.recvfrom(100)
        header, msg = extractHeader(data), data[5:].decode()
        clientSeq = header[0]
        
        if header[2]['FIN']:
            break

        if not header[2]['PSH']:
            continue
    
        print(f"Primit [seq:{header[0]} ack:{header[1]} flags:{[k for k,v  in header[2].items() if v]} msg:{msg} len:{len(msg)}]")
        
        mesajePrimite.add((header[0], msg))

        # trimit ACK
        serverAck = clientSeq + len(msg) + 1
        response = addHeader(seq=serverSeq, ack=serverAck, flags=['ACK'], data='')
        server.sendto(response, clientAdress)
        print(f"Trimit [seq:{serverSeq} ack:{serverAck} flags:['ACK']]")
    except socket.timeout:
        continue
    
print(" --- ")

# primesc FIN (break de mai sus)
header = extractHeader(data)
clientSeq = header[0]
serverAck = clientSeq + 1
print(f"Primit [seq:{header[0]} ack:{header[1]} flags:{[k for k,v  in header[2].items() if v]}]")


# trimit FIN/ACK si astept ACK
while True:

    # trimit FIN/ACK
    response = addHeader(seq=serverSeq, ack=serverAck,flags=['FIN','ACK'] , data='')
    server.sendto(response, clientAdress)
    print(f"Trimit [seq:{serverSeq} ack:{serverAck} flags:['FIN','ACK']]")

    # astept ACK
    try:
        data, clientAdress = server.recvfrom(100)
        header = extractHeader(data)
        clientAck = header[1]
        if not header[2]['ACK']:
            continue
        print(f"Primit [seq:{header[0]} ack:{header[1]} flags:{[k for k,v  in header[2].items() if v]} msg:{msg} len:{len(msg)}]")
        # am primit ACK => gata
        break
    except socket.timeout:
        # n am primit ACK, retrimit FIN/ACK
        continue
        
print("Gata")

mesajePrimite = [msj for (_,msj) in sorted(mesajePrimite)]
print(f"Mesaje primite: {mesajePrimite}")
