import socket as mysoc
import sys
import hmac
import cPickle as pickle


def auth_digest(digest, tlds1_digest, tlds2_digest):
    if hmac.compare_digest(digest, tlds1_digest):
        return ["1","cpp.cs.rutgers.edu"]
    if hmac.compare_digest(digest, tlds2_digest):
        return ["2","java.cs.rutgers.edu"]


def run():


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
    csockid, addr = client_socket.accept()
    print("accepted client")

    # init TLDS1 socket
    try:
        tlds1_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("Client socket open error %s" % err))

    tld1_addr = mysoc.gethostbyname("cpp.cs.rutgers.edu")
    tlds1_socket_binding = (tld1_addr, 60001)
    tlds1_socket.connect(tlds1_socket_binding)
    print("Connected TLDS1")

    # init TLDS2 socket
    try:
        tlds2_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("Client socket open error %s" % err))

    tld2_addr = mysoc.gethostbyname("java.cs.rutgers.edu")
    tlds2_socket_binding = (tld2_addr, 60002)
    tlds2_socket.connect(tlds2_socket_binding)
    print("Connected TLDS2")

    while True:
        challenge_digest = csockid.recv(100)
        challenge_digest_arr = pickle.loads(challenge_digest)
        print("Received challenge and digest from client")
        challenge = challenge_digest_arr[0]
        digest = challenge_digest_arr[1]

        tlds1_socket.send(challenge)
        print("tld1 sent")
        tlds2_socket.send(challenge)
        print("tld2 sent")

        tlds1_response = tlds1_socket.recv(100)
        print("tld1 responded")
        tlds2_response = tlds2_socket.recv(100)
        print("tld2 responded")

        tld_server = auth_digest(digest, tlds1_response, tlds2_response)
        if tld_server[0] == "1":
            tlds1_socket.send("True")
            tlds2_socket.send("False")
        else:
            tlds1_socket.send("False")
            tlds2_socket.send("True")
        csockid.send(tld_server[1])
        print("Sent TLD server to client: %s" %tld_server[1])


run()
