import socket as mysoc
import sys


def init_sockets():
    # init AS socket
    try:
        as_socket = mysoc.socket(mysoc.AF_INET, mysoc.SOCK_STREAM)
    except mysoc.error as err:
        print('{}\n'.format("AS socket open error %s" % err))

    as_host_name = sys.argv[1]
    as_addr = mysoc.gethostbyname(as_host_name)
    as_port = 51237
    as_server_binding = (as_addr, as_port)
    as_socket.connect(as_server_binding)


def open_files():
    fOut = open("RESOLVED.txt", "w+")
    dns_table = sys.argv[2]
    fHostnames = open(dns_table, "r")
    return fHostnames.readlines()


def run():
    init_sockets()
    fHostnamesList = open_files()
    



