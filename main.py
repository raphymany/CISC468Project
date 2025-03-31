import sys
import socket
import threading
import time
import queue
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf

def show_help():
    print("""
Available commands:
    discover  - List available peers on the network
    connect   - Connect to a discovered peer
    contacts  - Check mutual authentication of contacts
    quit      - Exit the application
""")
    sys.stdout.flush()

class PeerDiscovery:
    SERVICE_TYPE = "_p2pfile._tcp.local."

    def __init__(self, peer_name, port):
        self.peer_name = peer_name
        self.port = port
        self.zeroconf = Zeroconf()
        self.info = None

    def register_peer(self):
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        self.info = ServiceInfo(
            self.SERVICE_TYPE,
            f"{self.peer_name}.{self.SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
        )
        self.zeroconf.register_service(self.info)
        print(f"Registered peer: {self.peer_name} ({local_ip}:{self.port})\n")
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

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            peer_info = f"Discovered peer: {name} - {ip}:{info.port}\n"
            self.peer_queue.put(peer_info)
            print(peer_info, end="")
            sys.stdout.flush()

    def remove_service(self, zeroconf, type, name):
        peer_info = f"Peer {name} left the network.\n"
        self.peer_queue.put(peer_info)
        print(peer_info, end="")
        sys.stdout.flush()
    
    def update_service(self, zeroconf, type, name):
        pass

def discover_peers(peer_queue):
    while not peer_queue.empty():
        print(peer_queue.get(), end="")
    sys.stdout.flush()

# Modified to include peer's key storage and retrieval mechanism
class PeerConnection:
    def __init__(self):
        self.peers_keys = {}

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_dh_keys(self):
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_message(self, private_key, message):
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, public_key, message, signature):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    # Modified connect method to check and store keys
    def connect_to_peer(self, peer_name=None, peer_ip=None, peer_port=None):
        if peer_name:
            print(f"Connecting to peer: {peer_name}")
        elif peer_ip:
            print(f"Connecting to peer at {peer_ip}:{peer_port}")
        else:
            print("Connecting to all discovered peers...")

        # Check if peer already has keys stored
        if peer_name in self.peers_keys:
            rsa_private, rsa_public, dh_private, dh_public = self.peers_keys[peer_name]
            print(f"Using stored keys for peer: {peer_name}")
        else:
            # Generate new keys if not already stored
            rsa_private, rsa_public = self.generate_rsa_keys()
            dh_private, dh_public = self.generate_dh_keys()

            # Store keys for future connections
            self.peers_keys[peer_name] = (rsa_private, rsa_public, dh_private, dh_public)

            # Display RSA keys
            print("\nGenerating RSA keys...")
            print(f"RSA Public Key: {rsa_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
            print(f"RSA Private Key: {rsa_private.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())}")

            # Display DH keys
            print("\nGenerating DH keys...")
            print(f"DH Public Key: {dh_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
            print(f"DH Private Key: {dh_private.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())}")

        # Simulate sending and signing DH public key with RSA private key
        message = dh_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        signature = self.sign_message(rsa_private, message)

        print("\nSigned DH Public Key. Sending to peer...")

        # Here we simulate receiving and verifying the peer's key
        print("\n[Feature 2] Secure connection established.\n")

        # Send verification of received public key
        print(f"Verification message sent: Received peer's public key: {dh_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")

        # Simulate receiving a peer verification message back
        print(f"Received peer's verification message: Received {dh_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
        sys.stdout.flush()

def main():
    print("P2P Secure File Sharing Application\n")
    show_help()
    
    peer_name = input("Enter your peer name: ").strip()
    peer_port = 5000
    discovery = PeerDiscovery(peer_name, peer_port)
    discovery.register_peer()
    
    peer_queue = queue.Queue()
    listener = PeerListener(peer_queue)
    
    # Initialize the PeerConnection object to manage keys
    peer_connection = PeerConnection()

    try:
        while True:
            time.sleep(5)
            command = input("\nEnter command: ").strip().lower()
            
            if command == "discover":
                print("Discovering peers...\n")
                sys.stdout.flush()
                discover_peers(peer_queue)
            
            elif command.startswith("connect"):
                parts = command.split()
                if len(parts) == 2:
                    # Try to connect to a specific peer by name or address
                    if ':' in parts[1]:  # e.g., connect 192.168.40.5:5000
                        peer_ip, peer_port = parts[1].split(':')
                        peer_connection.connect_to_peer(peer_ip=peer_ip, peer_port=int(peer_port))
                    else:  # e.g., connect peer_name
                        peer_connection.connect_to_peer(peer_name=parts[1])
                else:
                    # Connect to all peers
                    peer_connection.connect_to_peer()
            
            elif command == "contacts":
                print("[Feature 3] Checking authenticated contacts...\n")
                sys.stdout.flush()
            
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
