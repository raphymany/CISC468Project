import sys
import base64
import socket
import threading
import time
import queue
import ssl
import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding  # Added padding here
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf


def show_help():
    print(""" 
Available commands:
    discover  - List available peers on the network
    connect   - Connect to a discovered peer
    contacts  - Check mutual authentication of contacts
    listmyfiles - List files shared by you
    listpeerfiles <peer_ip> - List files shared by a peer
    quit      - Exit the application
""")
    sys.stdout.flush()

class PeerDiscovery:
    SERVICE_TYPE = "_http._tcp.local."

    def __init__(self, peer_name, port):
        self.peer_name = peer_name
        self.port = port
        self.zeroconf = Zeroconf()
        self.info = None
        self.ecdh_private, self.ecdh_public = generate_ecdh_keys()  # Generate ECDH keys here

    def register_peer(self):
        # Hardcode the IP to localhost (127.0.0.1) for testing purposes
        local_ip = "127.0.0.1"
        
        # Broadcast the ECDH public key during registration in PEM format
        ecdh_public_key_pem = self.ecdh_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Remove the PEM header/footer and newlines
        public_key = ecdh_public_key_pem.decode()
        public_key = public_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
        
        # Register the peer in Zeroconf with the public key (no PEM format)
        self.info = ServiceInfo(
            self.SERVICE_TYPE,
            f"{self.peer_name}.{self.SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],  # Use the hardcoded IP
            port=self.port,
            properties={"publicKey": public_key}  # Store the cleaned-up public key
        )
        
        self.zeroconf.register_service(self.info)
        print(f"Registered peer: {self.peer_name} ({local_ip}:{self.port})")
        print(f"Public ECDH Public Key: {public_key}\n")  # Print the public key without PEM formatting
        
        sys.stdout.flush()
        time.sleep(2)

    def unregister_peer(self):
        if self.info:
            self.zeroconf.unregister_service(self.info)
        self.zeroconf.close()


class PeerListener:
    def __init__(self, peer_queue):
        self.zeroconf = Zeroconf()
        self.browser = ServiceBrowser(self.zeroconf, PeerDiscovery.SERVICE_TYPE, self)
        self.peer_queue = peer_queue
        self.peers = {}  # Store peer names as keys and IP/port as values

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            port = info.port  # Grab the peer's actual port
            peer_name = name.split('.')[0]  # Extract the peer's name from the service name
            self.peers[peer_name] = (ip, port)  # Store peer name as key, and (IP, port) as value

            peer_info = f"Discovered peer: {peer_name} - {ip}:{port}\n"
            
            # Try to get the public key from the properties
            public_key_pem = info.properties.get(b"publicKey")
            if public_key_pem:
                public_key = public_key_pem.decode().replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
                peer_info += f"  Public ECDH Key: {public_key}\n\n"
            
            self.peer_queue.put(peer_info)
            print(peer_info, end="")

    def remove_service(self, zeroconf, type, name):
        peer_name = name.split('.')[0]
        if peer_name in self.peers:
            del self.peers[peer_name]  # Remove peer by name
            
        peer_info = f"Peer {peer_name} left the network.\n"
        self.peer_queue.put(peer_info)
        print(peer_info, end="")

    def update_service(self, zeroconf, type, name):
        pass

def handle_client(self, client_socket, client_address):
    """Listen for incoming requests from peers."""
    try:
        data = client_socket.recv(4096).decode()
        if data == "Get Peer File List":
            # List the files in the shared folder and send them to the peer
            files = os.listdir(self.shared_folder)
            if files:
                file_list = "\n".join(files)
            else:
                file_list = "No shared files available."
            client_socket.sendall(file_list.encode())
        
        elif data.startswith("Request File:"):
            # Extract the requested filename
            filename = data.split(":", 1)[1]
            if os.path.exists(filename):
                client_socket.send(b"EXISTS "+str(os.path.getsize(filename)).encode('utf-8'))
                with open(filename, 'rb') as f:
                    bytes_read = f.read(1024)
                    while bytes_read:
                        client_socket.send(bytes_read)
                        bytes_read = f.read(1024)
                print(f"Sent: {filename}")
            else:
                client_socket.send(b"ERR")
        
        else:
            client_socket.sendall(b"Unknown request")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def request_file(peer_ip, peer_port, filename):
    """Request a specific file from a peer."""
    with socket.create_connection((peer_ip, peer_port), timeout=5) as s:
        # Send the request to the peer for a specific file
        s.sendall(f"Request File:{filename}".encode())
        
        response = s.recv(1024).decode()
        if response.startswith("EXISTS"):
            filesize = int(response.split()[1])
            print(f"File exists, size: {filesize} bytes")
            with open(f"{os.getcwd()}\\{filename}", 'wb') as f:
                bytes_received = 0
                while bytes_received < filesize:
                    bytes_read = s.recv(1024)
                    if not bytes_read:
                        break
                    f.write(bytes_read)
                    bytes_received += len(bytes_read)
            print(f"Downloaded: {filename}")
        else:
            print(f"File {filename} does not exist on the peer.")


# Generate RSA Keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def discover_peers(peer_queue):
    while not peer_queue.empty():
        print(peer_queue.get(), end="")
    sys.stdout.flush()

def discover_peers(peer_queue):
    while not peer_queue.empty():
        print(peer_queue.get(), end="")
    sys.stdout.flush()

def listmyfiles():
    shared_dir = "shared_files"
    if not os.path.exists(shared_dir):
        os.makedirs(shared_dir)
    files = os.listdir(shared_dir)
    if files:
        print("Available shared files:")
        for file in files:
            print(f"  - {file}")
    else:
        print("No files available for sharing.")
    sys.stdout.flush()

def listpeerfiles(peer_name, listener):
    """Request the file list from a peer by its name."""
    # Check if the peer name exists in the discovered peers
    if peer_name not in listener.peers:
        print(f"Error: Peer {peer_name} not found in discovered peers.")
        return

    # Get the IP and port of the peer
    peer_ip, peer_port = listener.peers[peer_name]
    print(f"\nContacting peer {peer_name} at {peer_ip}:{peer_port} to list files...")

    try:
        with socket.create_connection((peer_ip, peer_port), timeout=5) as s:
            s.sendall(b"Get Peer File List")  # Request file list
            data = s.recv(4096).decode()
            if data:
                print(f"Files available from {peer_name} ({peer_ip}:{peer_port}):")
                print(data)
            else:
                print(f"Peer {peer_name} ({peer_ip}:{peer_port}) has no shared files.")
    except ConnectionRefusedError:
        print(f"Error: Unable to connect to peer {peer_name} ({peer_ip}:{peer_port}). Connection refused.")
    except socket.timeout:
        print(f"Error: Connection to peer {peer_name} ({peer_ip}:{peer_port}) timed out.")
    except Exception as e:
        print(f"Error retrieving file list from peer {peer_name} ({peer_ip}:{peer_port}): {e}")

def main():
    print("P2P Secure File Sharing Application\n")
    show_help()

    peer_name = input("Enter your name for discovery: ").strip()
    peer_port = 5000
    discovery = PeerDiscovery(peer_name, peer_port)
    discovery.register_peer()

    peer_queue = queue.Queue()
    listener = PeerListener(peer_queue)

    try:
        while True:
            time.sleep(7)
            command = input("\nEnter command: ").strip()
            if command == "discover":
                print("Discovering peers...\n")
                sys.stdout.flush()
                discover_peers(peer_queue)

            elif command.startswith("connect"):
                pass  # Placeholder for actual connection logic

            elif command == "contacts":
                pass  # Placeholder for authentication logic

            elif command == "listmyfiles":
                listmyfiles()

            elif command.startswith("listpeerfiles"):
                parts = command.split()
                if len(parts) < 2:
                    print("Usage: listpeerfiles <peer_ip>")
                else:
                    listpeerfiles(parts[1], listener)

            elif command == "quit":
                print("Exiting application.\n")
                sys.stdout.flush()
                discovery.unregister_peer()
                sys.exit(0)

            else:
                print("Invalid command. Type 'help' for a list of commands.\n")
                sys.stdout.flush()

    except KeyboardInterrupt:
        discovery.unregister_peer()
        sys.exit(0)

if __name__ == "__main__":
    main()
