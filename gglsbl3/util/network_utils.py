'''
This utility module provides functions dealing with network stuff
e.g. ip format conversion
'''
import struct
import socket
def ip_to_int(addr):
    """
    Converts a ip address (string) to it's numeric representation (int)

    Example:
    >>> ip_to_int('127.0.0.1')
    2130706433
    """
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int_to_ip(addr):
    """
    Converts a the numeric representation of an ip address
    to an ip address strin

    Example:
    >>> int_to_ip(2130706433)
    '127.0.0.1'
    """
    return socket.inet_ntoa(struct.pack("!I", addr))
