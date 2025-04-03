import sys
import base64
import socket
import threading
import time
import queue
import ssl
import os  # Import os for file operations and generating random challenges
import random  # Import random for generating a random port
import json  # Import json for handling JSON data
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
    ss - Start a socket server to share files
    listmyfiles - List files shared by you
    quit      - Exit the application
""")
    sys.stdout.flush()

class PeerDiscovery:
    SERVICE_TYPE = "_secureshare._tcp.local."

    def __init__(self, peer_name, port):
        self.peer_name = peer_name
        self.port = port
        self.zeroconf = Zeroconf()
        self.info = None
        self.peers = {}  # Dictionary to store discovered peers (username -> (IP, port))
        self.ecdh_private, self.ecdh_public = generate_ecdh_keys()  # Generate ECDH keys here

    def register_peer(self):
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
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
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={"publicKey": public_key}  # Store the cleaned-up public key
        )
        
        self.zeroconf.register_service(self.info)
        print(f"Registered peer: {self.peer_name} ({local_ip}:{self.port})")
        print(f"Public ECDH Public Key: {public_key}")  # Print the public key without PEM formatting
        
        sys.stdout.flush()
        time.sleep(2)

    def unregister_peer(self):
        if self.info:
            self.zeroconf.unregister_service(self.info)
        self.zeroconf.close()


class PeerListener:
    def __init__(self, peer_queue, discovery):
        self.zeroconf = Zeroconf()
        self.browser = ServiceBrowser(self.zeroconf, PeerDiscovery.SERVICE_TYPE, self)
        self.peer_queue = peer_queue
        self.discovery = discovery  # Reference to the PeerDiscovery instance

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            peer_name = name.split(".")[0]  # Extract the peer name from the service name
            self.discovery.peers[peer_name] = (ip, info.port)  # Store the peer's IP and port
            
            peer_info = f"\nDiscovered peer: {peer_name} - {ip}:{info.port}\n"
            
            # Try to get the public key from the properties
            public_key_pem = info.properties.get(b"publicKey")

            if public_key_pem:
                public_key = public_key_pem.decode()  # Decode the PEM encoded public key
                public_key = public_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
                peer_info += f"  Public ECDH Key: {public_key}\n\n"
            
            self.peer_queue.put(peer_info)
            print(peer_info, end="")
            sys.stdout.flush()

    def remove_service(self, zeroconf, type, name):
        peer_name = name.split(".")[0]  # Extract the peer name from the service name
        if peer_name in self.discovery.peers:
            del self.discovery.peers[peer_name]  # Remove the peer from the dictionary
        
        peer_info = f"Peer {peer_name} left the network.\n"
        self.peer_queue.put(peer_info)
        print(peer_info, end="")
        sys.stdout.flush()

    def update_service(self, zeroconf, type, name):
        pass

def discover_peers(peer_queue):
    while not peer_queue.empty():
        print(peer_queue.get(), end="")
    sys.stdout.flush()

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

def listmyfiles():
    shared_dir = "shared_files"  # Directory where shared files are stored

    # Ensure the directory exists
    if not os.path.exists(shared_dir):
        os.makedirs(shared_dir)
        print(f"Shared directory '{shared_dir}' created. No files to list yet.")
        return

    # List files in the directory
    files = os.listdir(shared_dir)
    if files:
        print("Files you are sharing:")
        for file in files:
            print(f"  - {file}")
    else:
        print("No files are currently being shared.")

class SocketServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)  # Allow up to 5 connections
        print(f"Socket server started on {self.host}:{self.port}")
        sys.stdout.flush()  # Ensure the message is immediately printed

    def start(self):
        try:
            while True:
                print("Waiting for a connection...")
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
        except KeyboardInterrupt:
            print("Shutting down the server.")
            sys.stdout.flush()
            self.server_socket.close()

    def handle_client(self, client_socket):
        try:
            while True:
                # Send the menu to the client
                menu = (
                    "=== Server Menu ===\n"
                    "1. List Files\n"
                    "2. Download Files\n"
                    "3. Disconnect\n"
                    "Choose an option: "
                )
                client_socket.send(menu.encode('utf-8'))

                # Receive the client's choice
                try:
                    data = client_socket.recv(1024).decode('utf-8').strip()
                    if not data:
                        print("No data received. Closing connection.")
                        sys.stdout.flush()
                        break
                except ConnectionResetError:
                    print("Client disconnected unexpectedly.")
                    sys.stdout.flush()
                    break

                print(f"Client selected option: {data}")
                sys.stdout.flush()

                if data == "1":
                    # List files in the shared_files directory
                    shared_dir = "shared_files"
                    if not os.path.exists(shared_dir):
                        os.makedirs(shared_dir)

                    files = os.listdir(shared_dir)
                    if files:
                        file_list = "Files you are sharing:\n"
                        for file in files:
                            file_path = os.path.join(shared_dir, file)
                            file_size = os.path.getsize(file_path)  # Get file size
                            file_list += f"  - {file} ({file_size} bytes)\n"
                    else:
                        file_list = "No files are currently being shared.\n"

                    client_socket.send(file_list.encode('utf-8'))

                elif data == "2":
                    # Handle file download
                    shared_dir = "shared_files"
                    if not os.path.exists(shared_dir):
                        os.makedirs(shared_dir)

                    # Send the list of files to the client
                    files = os.listdir(shared_dir)
                    if files:
                        file_list = "Available files:\n"
                        for file in files:
                            file_path = os.path.join(shared_dir, file)
                            file_size = os.path.getsize(file_path)  # Get file size
                            file_list += f"  - {file} ({file_size} bytes)\n"
                        file_list += "Enter the file name(s) to download (comma-separated) or 'all' to download all files: "
                    else:
                        file_list = "No files are currently being shared.\n"

                    client_socket.send(file_list.encode('utf-8'))

                    # Receive the client's file request
                    try:
                        requested_files = client_socket.recv(1024).decode('utf-8').strip()
                        print(f"Client requested: {requested_files}")
                        sys.stdout.flush()
                    except ConnectionResetError:
                        print("Client disconnected before sending file request.")
                        sys.stdout.flush()
                        break

                    if requested_files.lower() == "all":
                        # Send all files
                        for file in files:
                            self.send_file(client_socket, os.path.join(shared_dir, file))
                        client_socket.send(b"END_OF_DOWNLOADS")  # Signal end of downloads
                    else:
                        # Send specific files
                        requested_files = [f.strip() for f in requested_files.split(",")]
                        for file in requested_files:
                            if file in files:
                                self.send_file(client_socket, os.path.join(shared_dir, file))
                            else:
                                error_message = f"File '{file}' not found.\n"
                                client_socket.send(error_message.encode('utf-8'))
                        client_socket.send(b"END_OF_DOWNLOADS")  # Signal end of downloads

                elif data == "3":
                    # Disconnect the client
                    print("Client chose to disconnect.")
                    sys.stdout.flush()
                    break

                else:
                    # Invalid option
                    error_message = "Invalid option. Please choose 1, 2, or 3.\n"
                    client_socket.send(error_message.encode('utf-8'))

        except ConnectionResetError:
            print("Client disconnected.")
            sys.stdout.flush()
        finally:
            print("Closing client connection.")
            sys.stdout.flush()
            client_socket.close()

    def send_file(self, client_socket, file_path):
        """Send a file to the client."""
        try:
            with open(file_path, "rb") as f:
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                # Notify client of file start with file name and size
                client_socket.send(f"START {file_name} {file_size}".encode('utf-8'))
                while chunk := f.read(1024):
                    client_socket.send(chunk)
                client_socket.send(b"END")  # Notify client of file end
            print(f"File '{file_name}' sent successfully.")
            sys.stdout.flush()
        except Exception as e:
            print(f"Error sending file '{file_path}': {e}")
            sys.stdout.flush()

def connect_to_peer(peer_ip, peer_port):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((peer_ip, peer_port))
        print(f"Connected to peer at {peer_ip}:{peer_port}")

        while True:
            # Receive data until we have the full menu
            data = b""
            while b"Choose an option:" not in data:
                chunk = client_socket.recv(1024)
                if not chunk:
                    raise ConnectionError("Server disconnected")
                data += chunk
            
            # Display menu
            menu = data.decode('utf-8')
            print(menu, end='')

            # Get and send choice
            choice = input().strip()
            client_socket.send(choice.encode('utf-8'))

            # Handle file download
            if choice == "2":
                # Receive the list of files or prompt
                file_list = client_socket.recv(1024).decode('utf-8')
                print(file_list, end='')

                # Send file request
                requested_files = input().strip()
                client_socket.send(requested_files.encode('utf-8'))

                # Receive files
                while True:
                    data = client_socket.recv(1024)
                    if data.startswith(b"START"):
                        # Parse file name and size
                        _, file_name, file_size = data.decode('utf-8').split(" ", 2)
                        file_size = int(file_size)
                        print(f"Receiving file: {file_name} ({file_size} bytes)")
                        with open(file_name, "wb") as f:
                            received_size = 0
                            while received_size < file_size:
                                chunk = client_socket.recv(1024)
                                if chunk == b"END":
                                    break
                                f.write(chunk)
                                received_size += len(chunk)
                            print(f"File '{file_name}' received successfully.")
                    elif data == b"END_OF_DOWNLOADS":
                        # Signal that all requested files have been sent
                        print("All requested files have been downloaded.")
                        break
                    else:
                        print(data.decode('utf-8'), end='')

            # Handle disconnect
            elif choice == "3":
                print("Disconnected from server.")
                break

    except ConnectionRefusedError:
        print(f"Could not connect to peer at {peer_ip}:{peer_port}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Client socket closed.")
        sys.stdout.flush()
        
def main():
    print("P2P Secure File Sharing Application\n")
    show_help()

    peer_name = input("Enter your peer name: ").strip()
    peer_port = random.randint(49152, 65535)  # Generate a random port in the dynamic/private range
    print(f"Assigned random port: {peer_port}")  # Inform the user of the assigned port

    discovery = PeerDiscovery(peer_name, peer_port)
    discovery.register_peer()

    peer_queue = queue.Queue()
    listener = PeerListener(peer_queue, discovery)

    try:
        while True:
            time.sleep(5)
            command = input("\nEnter command: ").strip().lower()

            if command == "discover":
                print("Discovering peers...\n")
                sys.stdout.flush()
                discover_peers(peer_queue)

            elif command == "connect":
                peer_username = input("Enter peer username: ").strip()
                if peer_username in discovery.peers:
                    peer_ip, peer_port = discovery.peers[peer_username]
                    connect_to_peer(peer_ip, peer_port)
                else:
                    print(f"Peer '{peer_username}' not found. Please discover peers first.")

            elif command == "ss":
                server = SocketServer("192.168.2.97", peer_port)  # Use the same random port
                print(f"Starting server on port {peer_port}")  # Inform the user of the server port
                threading.Thread(target=server.start, daemon=True).start()  # Use daemon threads to ensure proper shutdown

            elif command == "listmyfiles":
                listmyfiles()

            elif command == "quit":
                print("Exiting application.\n")
                sys.stdout.flush()
                discovery.unregister_peer()  # Unregister the peer from the network
                break  # Exit the loop to terminate the program

            else:
                print("Invalid command. Type 'help' for a list of commands.\n")
                sys.stdout.flush()

    except KeyboardInterrupt:
        print("\nForce shutdown detected. Cleaning up...")
        discovery.unregister_peer()  # Ensure the peer is unregistered
    finally:
        print("Goodbye!")
        sys.exit(0)  # Explicitly terminate the program

if __name__ == "__main__":
    main()
