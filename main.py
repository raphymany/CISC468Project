import sys
import socket
import threading
import time
import queue
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
        time.sleep(2)  # Allow peer discovery results to print first

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
            self.peer_queue.put(peer_info)  # Store peer info in the queue
            print(peer_info, end="")  # Ensure peer discovery prints immediately
            sys.stdout.flush()

    def remove_service(self, zeroconf, type, name):
        peer_info = f"Peer {name} left the network.\n"
        self.peer_queue.put(peer_info)
        print(peer_info, end="")  # Print immediately when a peer leaves
        sys.stdout.flush()
    
    def update_service(self, zeroconf, type, name):
        pass  # Fixes the FutureWarning issue

def discover_peers(peer_queue):
    while not peer_queue.empty():
        print(peer_queue.get(), end="")
    sys.stdout.flush()

def main():
    print("P2P Secure File Sharing Application\n")
    show_help()
    
    peer_name = input("Enter your peer name: ").strip()
    peer_port = 5000  # Default port for communication
    discovery = PeerDiscovery(peer_name, peer_port)
    discovery.register_peer()
    
    peer_queue = queue.Queue()
    listener = PeerListener(peer_queue)
    
    try:
        while True:
            time.sleep(5)  # Keep the main thread alive to allow discovery
            command = input("\nEnter command: ").strip().lower()
            
            if command == "discover":
                print("Discovering peers...\n")
                sys.stdout.flush()
                discover_peers(peer_queue)
            
            elif command == "connect":
                print("[Feature 2] Connecting to peer...\n")
                sys.stdout.flush()
            
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
