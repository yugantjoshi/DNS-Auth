import socket as mysoc
import sys
import hmac
import pickle

#TODO: Figure out how to send hmac over socket
#Run on java.cs.rutgers.edu
#python ./ASserver.py grep.cs.rutgers.edu null.cs.rutgers.edu

# def get_digest(line):
#     line.strip()
#     split_entry = line.split(" ")
#     return split_entry[1].strip("\n").strip("\r").strip()
#
#
# def get_challenge(line):
#     line.strip()
#     split_entry = line.split(" ")
#     return split_entry[0].strip("\n").strip("\r").strip()


def auth_digest(digest, tlds1_digest, tlds2_digest):
    if hmac.compare_digest(digest, tlds1_digest):
        return HN1
    if hmac.compare_digest(digest, tlds2_digest):
        return HN2


def run():

    HN1 = sys.argv[1]
    HN2 = sys.argv[2]

    #init Client Socket
    try:
        client_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("Client socket open error %s" % err))

    client_server_binding = ('', 50000)
    client_socket.bind(client_server_binding)
    client_socket.listen(1)
    client_socket.accept()
    print("accepted client")

    #init TLDS1 socket
    try:
        tlds1_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("Client socket open error %s" % err))

    tlds1_socket_binding = (HN1,60001)
    tlds1_socket.connect(tlds1_socket_binding)
    print("Connected TLDS1")

    #init TLDS2 socket
    try:
        tlds2_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("Client socket open error %s" % err))

    tlds2_socket_binding = (HN2, 60002)
    tlds2_socket.connect(tlds2_socket_binding)
    print("Connected TLDS2")

    while True:
        client_challenge = client_socket.recv(100)
        client_digest = pickle.loads(client_socket.recv(100))
        challenge = get_challenge(client_challenge)
        digest = get_digest(client_digest)

        tlds1_socket.send(challenge)
        tlds2_socket.send(challenge)

        tlds1_response = pickle.loads(tlds1_socket.recv(100))
        tlds2_response = pickle.loads(tlds2_socket.recv(100))

        tld_server = auth_digest(digest, tlds1_response, tlds2_response)
        client_socket.send(tld_server)

run()
