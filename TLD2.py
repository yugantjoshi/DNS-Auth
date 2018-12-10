import sys
import socket as mysoc
import hmac
import pickle

#TODO: Figure out how to send hmac over socket

def TLD2server():
    fDNSTLD2names = open("PROJ3-TLDS2.txt", "r")
    fDNSTLD2List = fDNSTLD2names.readlines()
    inputEntries = []
    for entry in fDNSTLD2List:
        inputEntries.append(entry.strip("\n"))

    try:
        as_socket=mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("AS socket open error",err))

    as_server_binding=('', 60002)
    as_socket.bind(as_server_binding)
    as_socket.listen(1)
    hostname = mysoc.gethostname()
    as_host_ip = (mysoc.gethostbyname(hostname))
    as_sockid, addr = as_socket.accept()

    keyfile = open("PROJ3-KEY2.txt", "r")
    key = keyfile.readline(100).strip("\n")

    client_con = False

    while True:
        challenge = as_sockid.recv(100)
        digest = hmac.new(key.encode(), challenge.encode("utf-8"))
        as_sockid.send(digest.digest())
        results  = as_sockid.recv(100)

        if results == "True":
            if not client_con:
                try:
                    client_socket=mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
                except mysoc.error as err:
                    print('{}\n'.format("client socket open error",err))

                client_socket_binding = ('', 50002)
                client_socket.bind(client_socket_binding)
                client_socket.listen(1)
                csockid, caddr = client_socket.accept()
                client_con = True

            client_data = csockid.recv(100)
            if client_data:
                foundEntry = False
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
                if not foundEntry:
                    print("[TLDS1:] Sending error")
                    csockid.send("%s - Error: HOST NOT FOUND" % client_data)
    as_socket.close()
    client_socket.close()
    exit()

TLD2server()
