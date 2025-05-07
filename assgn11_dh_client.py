import socket

P = int(input("Enter the prime number "))
G = int(input("Enter the Generator G "))
a = int(input("Enter the alice private key "))
A = pow(G, a, P)
print(f"Alice's public key {A}")

client_socket = socket.socket()
client_socket.connect(("localhost", 8080))

B = int(client_socket.recv(1024).decode())
client_socket.send(str(A).encode())
print(B)

shared_key = pow(B, a, P)
print(f"Shared key = {shared_key}")

client_socket.close()