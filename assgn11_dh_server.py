import socket

P = int(input("Enter the prime number "))
G = int(input("Enter the Generator G "))
b = int(input("Enter the server private key "))
B = pow(G, b, P)
print(f"server's public key {B}")

server_socket = socket.socket()
server_socket.bind(("localhost", 8080))
server_socket.listen(1)
print("Waiting for client....")

conn, addr = server_socket.accept()
print(f"Connected to {addr}")

conn.send(str(B).encode())

A = int(conn.recv(1024).decode())
print(A)

shared_key = pow(A, b, P)
print(f"Shared key = {shared_key}")

conn.close()