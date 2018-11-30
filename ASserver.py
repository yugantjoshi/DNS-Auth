import socket as mysoc
import sys
import hmac

#Run on java.cs.rutgers.edu
#python ./ASserver.py grep.cs.rutgers.edu null.cs.rutgers.edu

def get_digest(line):
    line.strip()
    split_entry = line.split(" ")
    return split_entry[1].strip("\n").strip("\r").strip()


def get_challenge(line):
    line.strip()
    split_entry = line.split(" ")
    return split_entry[0].strip("\n").strip("\r").strip()


def auth_digest(digest, tlds1_digest, tlds2_digest):
    if digest == tlds1_digest:
        return HN1
    if digest == tlds2_digest
        return HN2


def run():

    HN1 = sys.argv[1]
    HN2 = sys.argv[2]

    #init Client Socket
    try:
        client_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("Client socket open error %s" % err))

    #as_server_binding = ('', 51237) DONT think we need this lol
    client_socket.bind('',80000)
    client_socket.listen(1)
    client_socket.accept()
    print("accepted client")

    #init TLDS1 socket
    try:
        tlds1_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("Client socket open error %s" % err))

    tlds1_socket.connect(HN1,70001)
    print("Connected TLDS1")

    #init TLDS2 socket
    try:
        tlds2_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("Client socket open error %s" % err))

    tlds2_socket.connect(HN2,70002)
    print("Connected TLDS2")

    while True:
        client_challenge_digest = client_socket.recv(100)
        challenge = get_challenge(client_challenge_digest)
        digest = get_digest(client_challenge_digest)

        tlds1_socket.send(challenge)
        tlds2_socket.send(challenge)

        tlds1_response = tlds1_socket.recv(100)
        tlds2_response = tlds2_socket.recv(100)

        tld_server = auth_digest(digest, tlds1_response, tlds2_response)
        client_socket.send(tld_server)

run()
