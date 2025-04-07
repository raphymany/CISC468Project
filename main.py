import sys
import threading
import time
import queue
import random
from discoverListen import PeerDiscovery, PeerListener, discover_peers
from connection import connect_to_peer
from socket_server import SocketServer
from discoverListen import PeerDiscovery, PeerListener, discover_peers
from cryptoUtils import list_files

def show_help():
    print(""" 
Available commands:
    discover  - List available peers on the network
    connect   - Connect to a discovered peer
    ss - Start a socket server to share files
    list - List files shared by you
    quit      - Exit the application
""")
    sys.stdout.flush()

def main():
    # Prompt for the user's name and register the peer first
    peer_name = input("\nEnter your name for discovery: ").strip()
    peer_port = random.randint(49152, 65535)
    print(f"Assigned random port: {peer_port}")

    discovery = PeerDiscovery(peer_name, peer_port)
    discovery.register_peer()

    # Show the available commands menu after registration
    print("\nP2P Secure File Sharing Application")
    show_help()

    peer_queue = queue.Queue()
    listener = PeerListener(peer_queue, discovery)

    try:
        while True:
            time.sleep(5)
            command = input("\nEnter command: ").strip().lower()

            if command == "discover":
                print("Discovering peers...\n")
                sys.stdout.flush()
                discover_peers(peer_queue, discovery)

            elif command == "connect":
                peer_username = input("\nEnter peer username: ").strip()
                if peer_username in discovery.peers:
                    peer_ip, peer_port = discovery.peers[peer_username]
                    connect_to_peer(peer_ip, peer_port)
                else:
                    print(f"\nPeer '{peer_username}' not found. Please discover peers first.")

            elif command == "ss":
                server = SocketServer("192.168.40.5", peer_port)
                print(f"Starting server on port {peer_port}")
                threading.Thread(target=server.start, daemon=True).start()

            elif command == "list":
                list_files()

            elif command == "quit":
                print("Exiting application.\n")
                sys.stdout.flush()
                discovery.unregister_peer()
                break

            else:
                print("Invalid command. Type 'help' for a list of commands.\n")
                sys.stdout.flush()

    except KeyboardInterrupt:
        print("\nForce shutdown detected. Cleaning up...")
        discovery.unregister_peer()
    finally:
        print("Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()
