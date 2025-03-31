import time
import socket
import threading
import sys
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser

# Configuration
SERVICE_TYPE = "_testservice._tcp.local."
SERVICE_NAME = "My Test Service._testservice._tcp.local."
DISCOVERY_MESSAGE = b"Connected!"  # Message sent back to service


def get_local_ip():
    """Gets the actual local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to external server (Google DNS)
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())  # Fallback method


def get_available_port():
    """Finds an available port by binding to port 0 (letting OS choose)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 0))  # Bind to any available port
    port = s.getsockname()[1]
    s.close()
    return port


def udp_listener(port, stop_event):
    """Listens for a UDP message from the discovery client."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))  # Listen on all interfaces
    sock.settimeout(60)  # Timeout to prevent running indefinitely

    print(f"Service is waiting for a connection on port {port}...")

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(1024)  # Receive UDP message
            if data == DISCOVERY_MESSAGE:
                print(f"Discovery is connected to Service from {addr}!")
                stop_event.set()  # Stop the service gracefully
        except socket.timeout:
            pass  # Timeout and check stop_event again

    sock.close()


def run_service():
    """Advertises a service on the local network and waits for a connection."""
    local_ip = get_local_ip()
    port = get_available_port()  # Get a free port

    desc = {'info': 'This is a test service'}
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[socket.inet_aton(local_ip)],  # Convert IP to bytes
        port=port,
        properties=desc,
    )

    zeroconf = Zeroconf()
    print(f"Registering service: {SERVICE_NAME}")
    print(f"IP Address: {local_ip}, Port: {port}")  # Print IP & Port
    zeroconf.register_service(info)

    # Start a thread to listen for the discovery connection
    stop_event = threading.Event()
    listener_thread = threading.Thread(target=udp_listener, args=(port, stop_event))
    listener_thread.start()

    try:
        stop_event.wait()  # Wait until the discovery client connects
    finally:
        print("Unregistering service...")
        zeroconf.unregister_service(info)
        zeroconf.close()


class MyListener:
    def __init__(self):
        self.services = {}

    def add_service(self, zeroconf, service_type, name):
        """Handles newly discovered services."""
        info = zeroconf.get_service_info(service_type, name)
        if info:
            ip_address = socket.inet_ntoa(info.addresses[0])
            self.services[name] = (ip_address, info.port, info.properties)
            print(f"[INFO] Service {name} discovered!")
            print(f"       Address={ip_address}, Port={info.port}, Properties={info.properties}")

            # Send a connection message to the discovered service
            self.send_connection_message(ip_address, info.port)

    def remove_service(self, zeroconf, service_type, name):
        """Handles service removal."""
        if name in self.services:
            print(f"[INFO] Service {name} removed.")
            del self.services[name]

    def update_service(self, zeroconf, service_type, name):
        """Handles service updates (even if we don't use it)."""
        pass  

    def send_connection_message(self, ip, port):
        """Sends a UDP connection request to the discovered service."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(DISCOVERY_MESSAGE, (ip, port))
        sock.close()
        print(f"[INFO] Sent connection message to service at {ip}:{port}")


def discover_service():
    """Continuously listens for peer discovery messages."""
    zeroconf = Zeroconf()
    listener = MyListener()
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

    print("[INFO] Listening for peers... Press CTRL+C to stop.")
    
    try:
        while True:
            time.sleep(10)  # Keeps the program running to continuously listen
    except KeyboardInterrupt:
        print("[INFO] Discovery stopped.")
        zeroconf.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python PeerDiscovery.py [service|discover]")
        sys.exit(1)

    if sys.argv[1] == "service":
        run_service()
    elif sys.argv[1] == "discover":
        discover_service()
    else:
        print("Invalid argument. Use 'service' to advertise or 'discover' to search.")
