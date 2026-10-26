"""Prove the future SSH port is reachable before changing any SSH listener."""

import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(20)
    listener.bind(("0.0.0.0", int(sys.argv[1])))
    listener.listen(1)
    connection, _ = listener.accept()
    with connection:
        connection.sendall((sys.argv[2] + "\n").encode("ascii"))
