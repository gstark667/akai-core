from socket import *

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(("127.0.0.1", 6666))
addr, message = sock.recvfrom(1234)
print(addr)
print(message)
sock.sendto(b"1:ack", ("127.0.0.1", 6667))
sock.sendto(b"5:register", ("127.0.0.1", 6667))
addr, message = sock.recvfrom(1234)
print(addr)
print(message)
