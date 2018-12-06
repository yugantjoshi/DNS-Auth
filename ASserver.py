import socket as mysoc
import sys
import hmac
import pickle


def auth_digest(digest, tlds1_digest, tlds2_digest):
    if hmac.compare_digest(digest, tlds1_digest):
        pass
    if hmac.compare_digest(digest, tlds2_digest):
        pass


def run():

    tld1_addr = "cpp.cs.rutgers.edu"
    tld2_addr = "java.cs.rutgers.edu"

    #init Client Socket
    try:
        client_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("Client socket open error %s" % err))

    client_addr = mysoc.gethostname()
    client_port = 50000
    client_server_binding = (client_addr, client_port)
    client_socket.bind(client_server_binding)
    client_socket.listen(1)
    client_socket.accept()
    print("accepted client")

    client_data = client_socket.recv(100)
    client_data.encode('utf-8')
    print(client_data)

run()
