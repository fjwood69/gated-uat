import socket


def _safe_get():
    try:
        s = socket.create_connection(("health-proxy", 8080), 3)
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        r = s.recv(64); s.close()
        if b"503" in r: raise OSError("transient")
        return r
    except OSError:
        return b"unavailable"
for _ in range(3):
    r = _safe_get()
    if r: break
