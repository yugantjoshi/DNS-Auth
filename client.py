import socket as mysoc
import sys
import hmac
import cPickle as pickle


def open_files():
    dns_table = sys.argv[1]
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

    for line in fHostnamesList:
        # parse key, challenge, hostname
        line_key = get_piece(line, 0)
        line_challenge = get_piece(line, 1)
        line_hostname = get_piece(line, 2)
        # create digest
        digest = hmac.new(line_key.encode(), line_challenge.encode('utf-8'))
        digest_string = digest.digest()
        # send to AS
        # challenge_digest_array = [line_challenge, digest]
        # client_data = pickle.dumps(challenge_digest_array)
        as_socket.send(digest_string)
        print("[C:] Sending to AS %" % digest_string)

    as_socket.close()
    exit()

run()
