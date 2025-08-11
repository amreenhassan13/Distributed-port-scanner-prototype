import socket
import json
import nmap

CONTROLLER_IP = '127.0.0.1'  # localhost
CONTROLLER_PORT = 5055       

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((CONTROLLER_IP, CONTROLLER_PORT))

task = json.loads(client_socket.recv(8192).decode())
print(f"Received task: {task}")

scanner = nmap.PortScanner()
scanner.scan(task["ip"], task["ports"])

result = {}
for host in scanner.all_hosts():
    result[host] = {}
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()
        result[host][proto] = list(ports)

print("Scan result to send:", result)

client_socket.send(json.dumps(result).encode())
client_socket.close()
