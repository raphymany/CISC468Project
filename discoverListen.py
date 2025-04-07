import socket
import sys
import time
from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo

class PeerDiscovery:
    SERVICE_TYPE = "_secureshare._tcp.local."

    def __init__(self, peer_name, port):
        self.peer_name = peer_name
        self.port = port
        self.zeroconf = Zeroconf()
        self.info = None
        self.peers = {}

    def register_peer(self):
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # Register the peer in Zeroconf without generating ECDH keys
        self.info = ServiceInfo(
            self.SERVICE_TYPE,
            f"{self.peer_name}.{self.SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={}
        )

        self.zeroconf.register_service(self.info)
        print(f"Registered peer: {self.peer_name} ({local_ip}:{self.port})")
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
        self.discovery = discovery

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            peer_name = name.split(".")[0]
            self.discovery.peers[peer_name] = (ip, info.port)
            
            peer_info = f"\nDiscovered peer: {peer_name} - {ip}:{info.port}\n"
            
            self.peer_queue.put(peer_info)
            print(peer_info, end="")
            sys.stdout.flush()

    def remove_service(self, zeroconf, type, name):
        peer_name = name.split(".")[0]
        if peer_name in self.discovery.peers:
            del self.discovery.peers[peer_name]
        
        peer_info = f"Peer {peer_name} left the network.\n"
        self.peer_queue.put(peer_info)
        print(peer_info, end="")
        sys.stdout.flush()

    def update_service(self, zeroconf, type, name):
        pass

def discover_peers(peer_queue, discovery):
    """Display all currently discovered peers."""
    # Process any new peers in the queue
    while not peer_queue.empty():
        peer_queue.get()

    # Display all currently discovered peers
    if discovery.peers:
        print("Currently discovered peers:")
        for peer_name, (ip, port) in discovery.peers.items():
            print(f"  - {peer_name} - {ip}:{port}")
    else:
        print("\nNo peers currently discovered.")
    
    sys.stdout.flush()