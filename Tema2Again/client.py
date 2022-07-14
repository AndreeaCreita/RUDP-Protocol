import socket
import struct
import random

SERVER_HOST = 'localhost'
SERVER_PORT = 10000
SERVER = (SERVER_HOST, SERVER_PORT)
MAX_TIMEOUT = 0.3

FLAGS = {
    "SYN" : (1 << 7),
    "SEQ" : (1 << 6),
    "ACK" : (1 << 5),
    "PSH" : (1 << 4),
    "FIN" : (1 << 3)
}
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(MAX_TIMEOUT)

mesaje = ['salut', 'adwefje', '1234567']

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

clientSeq = None
clientAck = None
serverAck = None
serverSeq = None

# trimit SYN si astept SYN/ACK
while True:
    # trimit SYN
    clientSeq = random.randint(1, 10000)
    data = addHeader(seq=clientSeq, ack=0, flags=['SYN'], data='')
    client.sendto(data, SERVER)
    print(f"Trimit [seq:{clientSeq} ack:0 flags:['SYN'] msg:]")
    
    # astept SYN/ACK
    try:
        data, _ = client.recvfrom(100)
        header = extractHeader(data)
        serverAck = header[1]
        serverSeq = header[0]
        if not header[2]['ACK'] or not header[2]['SYN']:
            continue
        
        clientAck = serverSeq + 1
        clientSeq = serverAck
        print(f"Primit [seq:{header[0]} ack:{header[1]} flags:{[k for k,v  in header[2].items() if v]}]")
        # am primit SYN/ACK
        break
    except socket.timeout:
        # nu am primit SYN/ACK => retrimit SYN
        continue
        
# trimit ACK si astept mai mult, daca primesc SYN/ACK => nu a ajuns ACK la server
client.settimeout(5*MAX_TIMEOUT)
while True:
    # trimit ACK
    data = addHeader(seq=clientSeq, ack=clientAck, flags=['ACK'], data='')
    client.sendto(data, SERVER)
    print(f"Trimit [seq:{clientSeq} ack:{clientAck} flags:['ACK'] msg:]")

    # astept (mai mult) eventual SYN/ACK, daca il primesc => nu s a trimis ACK
    try:
        data, _ = client.recvfrom(100)
        header = extractHeader(data)
        serverAck = header[1]
        serverSeq = header[0]
        if not header[2]['ACK'] or not header[2]['SYN']:
            continue
    except socket.timeout:
        # nu am mai primit SYN/ACK => serverul a primit ACK si gata
        break

print(" --- ")

client.settimeout(MAX_TIMEOUT)
# trimit mesaje
for mesaj in mesaje:
    while True:
        try:
            # trimit mesaj cu PSH
            data = addHeader(seq=clientSeq, ack=clientAck, flags=['PSH'], data=mesaj)
            client.sendto(data, SERVER)
            print(f"Trimit [seq:{clientSeq} ack:{clientAck} flags:['PSH'] msg:{mesaj} len:{len(mesaj.encode())}]")
            
            # astept ACK
            data, _ = client.recvfrom(100)
            header = extractHeader(data)
            serverAck = header[1]
            if not header[2]['ACK'] or serverAck != clientSeq + len(mesaj) + 1:
                continue
            
            print(f"Primit [seq:{header[0]} ack:{header[1]} flags:{[k for k,v  in header[2].items() if v]}]")
            clientSeq = serverAck
            # am primit ACK, e ok trec la urm mesaj
            break
        except socket.timeout:
            # nu am primit ACk => retrimit mesaj cu PSH
            continue

print(' --- ')    
 
# trimit FIN si astept FIN/ACK

while True:
    try:
        # trimit FIN
        data = addHeader(seq=clientSeq, ack=clientAck, flags=['FIN'], data='')
        client.sendto(data, SERVER)
        print(f"Trimit [seq:{clientSeq} ack:{clientAck} flags:['FIN']")

        # astept FIN/ACK
        data, _ = client.recvfrom(100)
        header = extractHeader(data)
        print(f"Primit [seq:{header[0]} ack:{header[1]} flags:{[k for k,v  in header[2].items() if v]}]")
        serverSeq = header[0]
        clientAck = serverSeq + 1
        # am primit FIN/ACK
        break
    except socket.timeout:
        # am asteptat FIN/ACK si n am primit, trimit iar FIN si astept FIN/ACK
        continue

# trimit ACK si astept mai mult, daca primesc FIN/ACK => nu s a trimis ACK
client.settimeout(5*MAX_TIMEOUT)
while True:
    try:        
        # trimit ACK
        data = addHeader(seq=clientSeq, ack=clientAck, flags=['ACK'], data='')
        client.sendto(data, SERVER)
        print(f"Trimit [seq:{clientSeq} ack:{clientAck} flags:['ACK']]")

        # daca serverul nu primeste ACK trimite iar FIN/ACK
        
        # astept sa mai primesc FIN/ACK eventual
        data, _ = client.recvfrom(100)
        header = extractHeader(data)
        print(f"Primit [seq:{header[0]} ack:{header[1]} flags:{[k for k,v  in header[2].items() if v]}]")
        continue
    except socket.timeout:
        # serverul a primit ACK si nu a mai retrimis FIN/ACK
        break
    
print("Gata")
