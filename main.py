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

def list_my_files():
    # Use the script's directory as the base path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    shared_folder = os.path.join(script_dir, "shared_files")  # Define the shared_files folder path

    if not os.path.exists(shared_folder):
        print("No shared_files folder found. Please create one and add files to share.\n")
        return

    files = os.listdir(shared_folder)  # List all files in the shared_files folder
    if not files:
        print("No files available for sharing in the shared_files folder.\n")
    else:
        print("Files available for sharing:")
        for file in files:
            print(f"  - {file}")
    sys.stdout.flush()

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
                list_my_files()  # Call the list_my_files function

            elif command == "listpeerfiles":
                pass  # Placeholder for listing peer files

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
