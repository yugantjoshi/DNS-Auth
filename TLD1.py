import sys
import socket as mysoc
import hmac
import pickle

#TODO: Figure out how to send hmac over socket

def RSserver():

    fDNSRSnames = open("PROJ3-TLDS1.txt", "r")
    fDNSRSList = fDNSRSnames.readlines()
    inputEntries = []
    for entry in fDNSRSList:
        inputEntries.append(entry.strip("\n"))

    try:
        as_socket=mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("AS socket open error",err))

    as_server_binding=('', 60001)
    as_socket.bind(as_server_binding)
    as_socket.listen(1)
    hostname = mysoc.gethostname()
    as_host_ip = (mysoc.gethostbyname(hostname))
    as_sockid, addr = as_socket.accept()

    while True:
        keyfile = open("PROJ3-KEY1.txt", "r")
        key = keyfile.readline(100).strip("\n")
        challenge = as_sockid.recv(100)
        digest = hmac.new(key.encode(), challenge.encode("utf-8"))
        as_sockid.send(digest.digest())


        try:
            client_socket=mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
        except mysoc.error as err:
            print('{}\n'.format("client socket open error",err))

        client_socket_binding = ('', 50001)
        client_socket.bind(client_socket_binding)
        client_socket.listen(1)
        csockid, caddr = client_socket.accept()

        client_data = csockid.recv(100)
        foundEntry = False
        if not client_data:
            break
        client_data = client_data.strip("\n")
        client_data = client_data.strip("\r")
        print("[TLDS1:] Recieved: %s" % client_data)

        for entry in inputEntries:
            splitEntry = entry.split(" ")
            entryHostname = splitEntry[0].strip("\n")
            entryHostname = splitEntry[0].strip("\r")
            entryHostname = splitEntry[0].strip()
            flag = splitEntry[-1]
            flag = flag.strip()

            if entryHostname == client_data:
                foundEntry = True
                print("[TLDS1:] Sending: %s" % entry)
                csockid.send(entry)
                client_socket.close()
                break
            if flag == 'NS':
                if  not foundEntry:
                    print("[TLDS1:] Sending NS")
                    csockid.send(entry)
                    client_socket.close()

    as_socket.close()
    exit()

RSserver()
