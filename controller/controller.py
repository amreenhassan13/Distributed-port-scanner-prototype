import socket
import json
from queue import Queue

targets = Queue()
for t in [
    {"ip": "192.168.1.10", "ports": "20-25"},
    {"ip": "192.168.1.11", "ports": "80-85"},
    {"ip": "192.168.1.12", "ports": "22,80"},
]:
    targets.put(t)

HOST = ''
PORT = 5055  

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

print("Controller ready. Waiting for workers...")

while not targets.empty():
    conn, addr = server_socket.accept()
    print(f"Worker connected from {addr}")

    task = targets.get()
    conn.send(json.dumps(task).encode())

    data = conn.recv(8192).decode()
    result = json.loads(data)
    print(f"Result from worker for {task['ip']}:", result)

    conn.close()

server_socket.close()
print("All tasks done.")
