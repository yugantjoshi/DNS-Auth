import sys
import socket as mysoc
import hmac

#RUN ON grep.cs.rutgers.edu
#python ./TLD1.py PROJ3-KEY1.txt PROJ3-TLDS1.txt

def RSserver():

    fDNSRSnames = open(sys.argv[2], "r")
    fDNSRSList = fDNSRSnames.readlines()
    inputEntries = []
    for entry in fDNSRSList:
        inputEntries.append(entry.strip("\n"))

    try:
        as_socket=mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("AS socket open error",err))

    as_server_binding=('', 70001)
    as_socket.bind(as_server_binding)
    as_socket.listen(1)
    hostname = mysoc.gethostname()
    as_host_ip = (mysoc.gethostbyname(hostname))
    csockid,addr=as_socket.accept()

    while True:
        challenge = as_socket.recv(100)
        digest = hmac.new(key.encode(),challenge.encode("utf-8"))
        as_socket.send(digest)


        try:
            client_socket=mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
        except mysoc.error as err:
            print('{}\n'.format("client socket open error",err))

        client_socket.bind('', 80001)
        client_socket.listen(1)
        client_socket.accept()

        client_data = client_socket.recv(100)
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
                client_socket.send(entry)
                client_socket.close()
                break
            if flag == 'NS':
                if foundEntry == False:
                    print("[TLDS1:] Sending NS")
                    client_socket.send(entry)
                    client_socket.close()

    as_socket.close()
    exit()

RSserver()
