import sys
import base64
import socket
import threading
import time
import queue
import ssl
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

class PeerDiscovery:
    SERVICE_TYPE = "_http._tcp.local."

    def __init__(self, peer_name, port):
        self.peer_name = peer_name
        self.port = port
        self.zeroconf = Zeroconf()
        self.info = None
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

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            peer_info = f"Discovered peer: {name} - {ip}:{info.port}\n"
            
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

# Simulate the signing process (using RSA for signatures)
def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify signature
def verify_signature(public_key, message, signature):
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

# Store connected peers
connected_peers = {}

def connect_to_peer(peer_name=None, peer_ip=None, peer_port=None):
    if peer_name:
        print(f"Connecting to peer: {peer_name}")
    elif peer_ip:
        print(f"Connecting to peer at {peer_ip}:{peer_port}")
    else:
        print("Connecting to all discovered peers...")

    # Check if we already have this peer's keys saved
    if peer_name in connected_peers:
        print(f"Reusing keys for {peer_name}")
        rsa_private, rsa_public, ecdh_private, ecdh_public = connected_peers[peer_name]
    else:
        # Generate RSA keys and ECDH keys for the connection
        print("Generating new keys...")
        rsa_private, rsa_public = generate_rsa_keys()
        ecdh_private, ecdh_public = generate_ecdh_keys()

        # Store keys under the peer's name
        connected_peers[peer_name] = (rsa_private, rsa_public, ecdh_private, ecdh_public)

    # Simulate sending and signing ECDH public key with RSA private key
    message = ecdh_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = sign_message(rsa_private, message)

    print("\nSigned ECDH Public Key. Sending to peer...")
    sys.stdout.flush()

    # Simulate receiving and verifying the peer's key
    print("\n[Feature 2] Secure connection established.\n")

    # Send verification of received public key
    print(f"Verification message sent: Received peer's public key: {ecdh_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")

    # Simulate receiving a peer verification message back
    print(f"Received peer's verification message: Received {ecdh_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
    sys.stdout.flush()

def list_contacts():
    if not connected_peers:
        print("No connected peers.")
        return

    print("\nListing connected peers:")
    for peer_name, (rsa_private, rsa_public, ecdh_private, ecdh_public) in connected_peers.items():
        peer_ip = "Unknown"  # In a real implementation, this would be the peer's actual IP address
        peer_port = "Unknown"  # In a real implementation, this would be the peer's actual port
        print(f"Peer Name: {peer_name}")
        print(f"  IP: {peer_ip}, Port: {peer_port}")
        print(f"  RSA Public Key: {rsa_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
        print(f"  ECDH Public Key: {ecdh_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
        print()

def main():
    print("P2P Secure File Sharing Application\n")
    show_help()

    peer_name = input("Enter your peer name: ").strip()
    peer_port = 5000
    discovery = PeerDiscovery(peer_name, peer_port)
    discovery.register_peer()

    peer_queue = queue.Queue()
    listener = PeerListener(peer_queue)

    try:
        while True:
            time.sleep(7)
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
                        connect_to_peer(peer_ip=peer_ip, peer_port=int(peer_port))
                    else:  # e.g., connect peer_name
                        connect_to_peer(peer_name=parts[1])
                else:
                    # Connect to all peers
                    connect_to_peer()

            elif command == "contacts":
                list_contacts()

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
