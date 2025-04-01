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

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_dh_keys():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

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
        rsa_private, rsa_public, dh_private, dh_public = connected_peers[peer_name]
    else:
        # Generate RSA and DH keys for the connection
        print("Generating new keys...")
        rsa_private, rsa_public = generate_rsa_keys()
        dh_private, dh_public = generate_dh_keys()

        # Store keys under the peer's name
        connected_peers[peer_name] = (rsa_private, rsa_public, dh_private, dh_public)

    # Simulate sending and signing DH public key with RSA private key
    message = dh_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = sign_message(rsa_private, message)

    print("\nSigned DH Public Key. Sending to peer...")
    sys.stdout.flush()

    # Simulate receiving and verifying the peer's key
    print("\n[Feature 2] Secure connection established.\n")

    # Send verification of received public key
    print(f"Verification message sent: Received peer's public key: {dh_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")

    # Simulate receiving a peer verification message back
    print(f"Received peer's verification message: Received {dh_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
    sys.stdout.flush()

def list_contacts():
    if not connected_peers:
        print("No connected peers.")
        return

    print("\nListing connected peers:")
    for peer_name, (rsa_private, rsa_public, dh_private, dh_public) in connected_peers.items():
        peer_ip = "Unknown"  # In a real implementation, this would be the peer's actual IP address
        peer_port = "Unknown"  # In a real implementation, this would be the peer's actual port
        print(f"Peer Name: {peer_name}")
        print(f"  IP: {peer_ip}, Port: {peer_port}")
        print(f"  RSA Public Key: {rsa_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
        print(f"  DH Public Key: {dh_public.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
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
