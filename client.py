import socket as mysoc
import sys
import hmac
import pickle


def open_files():
    dns_table = sys.argv[2]
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

    as_addr = mysoc.gethostbyname(mysoc.gethostname())
    as_port = 50000
    as_server_binding = (as_addr, as_port)
    as_socket.connect(as_server_binding)
    fOut = open("RESOLVED.txt", "w+")
    fHostnamesList = open_files()

    for line in fHostnamesList:
        # parse key, challenge, hostname
        line_key = get_piece(line, 0)
        line_challenge = get_piece(line, 1)
        line_hostname = get_piece(line, 2)
        # create digest
        digest = hmac.new(line_key.encode(), line_challenge.encode('utf-8'))
        # send to AS
        as_socket.send(pickle.dumps(digest))
        print("[C:] Sending to AS %s" % line_challenge + " " + digest)

        # receive from AS
        as_data = as_socket.recv(100).strip()
        if as_data:
            try:
                tld_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
            except mysoc.error as err:
                print('{}\n'.format("tld socket open error %s" % err))

            tld_socket.connect(as_data, 50001)
            tld_socket.send(line_hostname)
            tld_data = tld_socket.recv(100).strip()
            fOut.write("%s\n" % tld_data)

    as_socket.close()
    exit()

run()
