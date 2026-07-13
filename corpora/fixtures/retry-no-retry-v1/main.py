import socket

s = socket.create_connection(("health-proxy", 8080), 3)
s.sendall(b"GET / HTTP/1.0\r\n\r\n"); s.recv(64); s.close()
