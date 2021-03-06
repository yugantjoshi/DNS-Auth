import socket as mysoc
import sys
import hmac
import cPickle as pickle


def open_files():
    dns_table = "PROJ3-HNS.txt"
    fHostnames = open(dns_table, "r")
    return fHostnames.readlines()


# Given line and index return either key, challenge, hostname
def get_piece(line, arg):
    split_entry = line.split(" ")
    return split_entry[arg].strip("\n").strip("\r").strip()


def run():
    # init AS socket
    try:
        as_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("AS socket open error %s" % err))

    as_addr = mysoc.gethostname()
    as_port = 50000
    as_server_binding = (as_addr, as_port)
    as_socket.connect(as_server_binding)
    fOut = open("RESOLVED.txt", "w+")
    fHostnamesList = open_files()

    tld1Con = False
    tld2con = False

    for line in fHostnamesList:
        # parse key, challenge, hostname
        line_key = get_piece(line, 0)
        line_challenge = get_piece(line, 1)
        line_hostname = get_piece(line, 2)
        # create digest
        digest = hmac.new(line_key.encode(), line_challenge.encode('utf-8'))
        digest_string = digest.digest()
        # send to AS
        challenge_digest_array = [line_challenge, digest_string]
        # client_data = pickle.dumps(challenge_digest_array)
        print("Sending challenge and digest to AS")
        as_socket.send(pickle.dumps(challenge_digest_array))
        tld_server = as_socket.recv(100)
        print("Recieved TLD Server from AS: %s" % tld_server)
        if tld_server == "cpp.cs.rutgers.edu":
            if not tld1Con:
                try:
                    tld1_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
                except mysoc.error as err:
                    print('{}\n'.format("tld socket open error %s" % err))

                tld_server_binding = (mysoc.gethostbyname(tld_server), 50001)
                tld1_socket.connect(tld_server_binding)
                tld1Con = True
            tld1_socket.send(line_hostname)
            print("Sending Data to TLD1 %s" % line_hostname)
            tld1_data = tld1_socket.recv(100).strip()
            print("Received Data from TLD1 %s" %tld1_data)
            fOut.write("TLDS1: %s\n" % tld1_data)
        elif tld_server == "java.cs.rutgers.edu":
            if not tld2con:
                try:
                    tld2_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
                except mysoc.error as err:
                    print('{}\n'.format("tld socket open error %s" % err))

                tld2_server_binding = (mysoc.gethostbyname(tld_server), 50002)
                tld2_socket.connect(tld2_server_binding)
                tld2con = True
            tld2_socket.send(line_hostname)
            print("Sending Data to TLD2 %s" % line_hostname)
            tld2_data = tld2_socket.recv(100).strip()
            print("Received Data from TLD2 %s" % tld1_data)
            fOut.write("TLDS2: %s\n" % tld2_data)

    as_socket.close()
    tld1_socket.close()
    tld2_socket.close()
    exit()

run()
