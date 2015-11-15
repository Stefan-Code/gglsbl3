import struct
import socket
def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))
