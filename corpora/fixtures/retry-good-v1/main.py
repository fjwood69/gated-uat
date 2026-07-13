import socket


def _get():
    s = socket.create_connection(("health-proxy", 8080), 3)
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    r = s.recv(64); s.close()
    if b"503" in r: raise OSError("transient")
    return r
for _ in range(3):
    try:
        _get(); break
    except OSError:
        continue
