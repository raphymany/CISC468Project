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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf


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

class PeerDiscovery:
    SERVICE_TYPE = "_secureshare._tcp.local."

    def __init__(self, peer_name, port):
        self.peer_name = peer_name
        self.port = port
        self.zeroconf = Zeroconf()
        self.info = None
        self.peers = {}  # Dictionary to store discovered peers (username -> (IP, port))

    def register_peer(self):
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # Register the peer in Zeroconf without generating ECDH keys
        self.info = ServiceInfo(
            self.SERVICE_TYPE,
            f"{self.peer_name}.{self.SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={}  # No public key is broadcasted during registration
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
        self.discovery = discovery  # Reference to the PeerDiscovery instance

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            peer_name = name.split(".")[0]  # Extract the peer name from the service name
            self.discovery.peers[peer_name] = (ip, info.port)  # Store the peer's IP and port
            
            peer_info = f"\nDiscovered peer: {peer_name} - {ip}:{info.port}\n"
            
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

def discover_peers(peer_queue, discovery):
    """Display all currently discovered peers."""
    # Process any new peers in the queue (but do not print them here)
    while not peer_queue.empty():
        peer_queue.get()  # Clear the queue without printing

    # Display all currently discovered peers
    if discovery.peers:
        print("Currently discovered peers:")
        for peer_name, (ip, port) in discovery.peers.items():
            print(f"  - {peer_name} - {ip}:{port}")
    else:
        print("\nNo peers currently discovered.")
    
    sys.stdout.flush()

def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def list_files():
    shared_dir = "shared_files"  # Directory where shared files are stored

    # Ensure the directory exists
    if not os.path.exists(shared_dir):
        os.makedirs(shared_dir)
        print(f"Shared directory '{shared_dir}' created. No files to list yet.")
        return

    # List files in the directory
    files = os.listdir(shared_dir)
    if files:
        print("\nFiles you are sharing:")
        for file in files:
            print(f"  - {file}")
    else:
        print("No files are currently being shared.")

def encrypt_file_data(data, session_key):
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    encryptor = Cipher(
        algorithms.AES(session_key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

class SocketServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)  # Allow up to 5 connections
        print(f"Socket server started on {self.host}:{self.port}")
        sys.stdout.flush()  # Ensure the message is immediately printed

        # Generate ECDH key pair for the server
        self.private_key, self.public_key = generate_ecdh_keys()

    def start(self):
        try:
            while True:
                print("Server is listening for incoming connections...")
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
        except KeyboardInterrupt:
            print("Shutting down the server.")
            sys.stdout.flush()
            self.server_socket.close()

    def handle_client(self, client_socket):
        try:
            # Step 1: Exchange public keys
            print("\nExchanging public keys for ECDH...")
            sys.stdout.flush()

            # Send server's public key in DER format
            server_public_key_der = self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(server_public_key_der)

            # Debugging: Print the raw key data
            print(f"Sent key (DER): {server_public_key_der.hex()}")

            # Receive client's public key in DER format
            client_public_key_der = client_socket.recv(1024)
            print(f"Received key (DER): {client_public_key_der.hex()}")
            client_public_key = serialization.load_der_public_key(
                client_public_key_der,
                backend=default_backend()
            )

            # Step 2: Generate shared secret
            shared_secret = self.private_key.exchange(ec.ECDH(), client_public_key)

            # Step 3: Derive session key using a KDF
            session_key = self.derive_session_key(shared_secret)
            print(f"Session key established: {session_key.hex()}")
            sys.stdout.flush()

            # Proceed with the rest of the communication (e.g., file sharing)
            self.secure_communication(client_socket, session_key)

        except Exception as e:
            print(f"Error during client handling: {e}")
            sys.stdout.flush()
        finally:
            print("Closing client connection.")
            sys.stdout.flush()
            client_socket.close()

    def derive_session_key(self, shared_secret):
        """Derive a session key from the shared secret using PBKDF2."""
        salt = b"secure_salt"  # Use a fixed salt for simplicity (can be randomized)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit session key
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(shared_secret)

    def secure_communication(self, client_socket, session_key):
        """Secure communication using the session key."""
        print("Secure communication established. Proceeding with menu...")
        sys.stdout.flush()

        while True:
            time.sleep(3)
            menu = (
                "\n=== Server Menu ===\n"
                "1. List Files\n"
                "2. Request File (with consent)\n"
                "3. Send File (with consent)\n"
                "4. Disconnect\n"
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

            # Handle menu options
            if data == "1":
                self.list_files_for_client(client_socket)  # Send file list to the client
            elif data == "2":
                self.handle_file_request_with_consent(client_socket, session_key)
            elif data == "3":
                self.handle_file_send_with_consent(client_socket, session_key)
            elif data == "4":
                print("Client chose to disconnect.")
                sys.stdout.flush()
                break
            else:
                error_message = "Invalid option. Please choose 1, 2, 3, or 4.\n"
                client_socket.send(error_message.encode('utf-8'))

    def list_files_for_client(self, client_socket):
        """List files in the shared_files directory and send them to the client."""
        shared_dir = "shared_files"  # Directory where shared files are stored

        # Ensure the directory exists
        if not os.path.exists(shared_dir):
            os.makedirs(shared_dir)

        # List files in the directory
        files = os.listdir(shared_dir)
        if files:
            file_list = "\nFiles you are sharing:\n"
            for file in files:
                file_list += f"  - {file}\n"
        else:
            file_list = "No files are currently being shared.\n"

        # Send the file list to the client
        client_socket.send(file_list.encode('utf-8'))

    def handle_file_request_with_consent(self, client_socket, session_key):
        """Handle a file request from the client with consent."""
        shared_dir = "shared_files"
        if not os.path.exists(shared_dir):
            os.makedirs(shared_dir)

        # Send the list of files in the shared_files directory to the client
        files = os.listdir(shared_dir)
        if files:
            file_list = "\nAvailable files:\n"
            for file in files:
                file_path = os.path.join(shared_dir, file)
                file_size = os.path.getsize(file_path)  # Get file size
                file_list += f"  - {file} ({file_size} bytes)\n"
            file_list += "\nEnter the file name to request: "
        else:
            file_list = "\nNo files are currently being shared.\n"

        client_socket.send(file_list.encode('utf-8'))
        print(f"[DEBUG] Sent file list to client: {file_list}")

        # Receive the client's file request
        try:
            requested_file = client_socket.recv(1024).decode('utf-8').strip()
            print(f"[DEBUG] Client requested file: {requested_file}")
        except ConnectionResetError:
            print("[DEBUG] Client disconnected before sending file request.")
            return

        if requested_file in files:
            # Ask the server user for consent
            print(f"Client requested '{requested_file}'. Allow? (yes/no): ", end="")
            sys.stdout.flush()

            # Wait for consent input
            consent = input().strip().lower()
            if consent == "yes":
                print(f"[DEBUG] Consent granted for file: {requested_file}")
                self.send_file(client_socket, os.path.join(shared_dir, requested_file), session_key)  # Pass session_key
            else:
                print(f"[DEBUG] Consent denied for file: {requested_file}")
                client_socket.send(f"Request to download '{requested_file}' denied.\n".encode('utf-8'))
        else:
            error_message = f"\nFile '{requested_file}' not found.\n"
            print(f"[DEBUG] {error_message.strip()}")
            client_socket.send(error_message.encode('utf-8'))

    def handle_file_send_with_consent(self, client_socket, session_key):
        """Handle receiving a file from the client with consent."""
        shared_dir = "shared_files"
        downloads_dir = "downloads"

        # Ensure the directories exist
        if not os.path.exists(shared_dir):
            os.makedirs(shared_dir)
        if not os.path.exists(downloads_dir):
            os.makedirs(downloads_dir)

        # List files in the shared_files directory
        files = os.listdir(shared_dir)
        if files:
            file_list = "\nFiles available to send:\n"
            for file in files:
                file_path = os.path.join(shared_dir, file)
                file_size = os.path.getsize(file_path)  # Get file size
                file_list += f"  - {file} ({file_size} bytes)\n"
            file_list += "\nEnter the file name to send: "
        else:
            file_list = "No files are available to send.\n"

        client_socket.send(file_list.encode('utf-8'))

        # Receive the client's file choice
        try:
            selected_file = client_socket.recv(1024).decode('utf-8').strip()
            print(f"Client wants to send: {selected_file}")
            sys.stdout.flush()
        except ConnectionResetError:
            print("Client disconnected before sending file choice.")
            sys.stdout.flush()
            return

        if selected_file in files:
            # Ask the server user for consent
            print(f"Do you accept the file '{selected_file}'? (yes/no): ", end="")
            sys.stdout.flush()

            # Wait for consent input
            consent = input().strip().lower()
            if consent == "yes":
                client_socket.send(f"Consent granted for '{selected_file}'.".encode('utf-8'))

                # Receive the START signal
                start_msg = client_socket.recv(1024).decode('utf-8')
                if not start_msg.startswith("START"):
                    print("Invalid start message.")
                    return

                try:
                    _, file_name, file_size = start_msg.split(" ", 2)
                    file_size = int(file_size)
                except ValueError:
                    print("Malformed START message.")
                    return

                # Save the file in the downloads directory
                file_path = os.path.join(downloads_dir, file_name)
                with open(file_path, "wb") as f:
                    while True:
                        chunk = client_socket.recv(1024)
                        if b"END_OF_FILE" in chunk:
                            # Cleanly strip out the marker
                            chunk = chunk.replace(b"END_OF_FILE", b"")
                            f.write(chunk)
                            break
                        f.write(chunk)
                print(f"Received file '{file_name}' from client and saved in 'downloads' folder.")
            else:
                client_socket.send(f"Request to send '{selected_file}' denied.\n".encode('utf-8'))
        else:
            error_message = f"\nFile '{selected_file}' not found.\n"
            client_socket.send(error_message.encode('utf-8'))

    def send_file(self, client_socket, file_path, session_key):
        """Send a file to the client with encryption."""
        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)

            # Send the START signal with file name and size
            start_message = f"START {file_name} {file_size}"
            client_socket.send(start_message.encode('utf-8'))
            print(f"[DEBUG] Sent START message: {start_message}")

            # Encrypt and send the file in chunks
            with open(file_path, "rb") as f:
                while chunk := f.read(1024):
                    nonce, ciphertext, tag = encrypt_file_data(chunk, session_key)
                    print(f"[DEBUG] Encrypting chunk: Nonce={nonce.hex()}, Tag={tag.hex()}, Ciphertext={ciphertext.hex()[:64]}...")  # Log encryption details
                    client_socket.send(nonce + tag + ciphertext)  # Send nonce, tag, and ciphertext
                    print(f"[DEBUG] Sent encrypted chunk of size {len(ciphertext)} bytes")

            # Send the END_OF_FILE marker
            client_socket.send(b"END_OF_FILE")
            print(f"[DEBUG] Sent END_OF_FILE marker for file '{file_name}'")

            print(f"File '{file_name}' sent successfully with encryption.")
        except Exception as e:
            print(f"Error while sending file '{file_path}': {e}")
            client_socket.send(f"Error while sending file '{file_name}'.\n".encode('utf-8'))

def connect_to_peer(peer_ip, peer_port):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((peer_ip, peer_port))
        print(f"\nConnected to peer at {peer_ip}:{peer_port}")

        # Step 1: Exchange public keys
        print("Exchanging public keys for ECDH...")
        sys.stdout.flush()

        # Generate ECDH key pair for the client
        private_key, public_key = generate_ecdh_keys()

        # Send client's public key in DER format
        client_public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(client_public_key_der)
        print(f"Sent key (DER): {client_public_key_der.hex()}")

        # Receive server's public key in DER format
        server_public_key_der = client_socket.recv(1024)
        if len(server_public_key_der) < 90:  # Validate key length
            raise ValueError("Invalid public key received from server.")
        print(f"Received key (DER): {server_public_key_der.hex()}")
        server_public_key = serialization.load_der_public_key(
            server_public_key_der,
            backend=default_backend()
        )

        # Step 2: Generate shared secret
        shared_secret = private_key.exchange(ec.ECDH(), server_public_key)
        print(f"Generated shared secret: {shared_secret.hex()}")

        # Step 3: Derive session key using SHA-256
        session_key = derive_session_key(shared_secret)
        print(f"Derived session key: {session_key.hex()}")
        sys.stdout.flush()

        # Proceed with the rest of the communication (e.g., menu handling)
        communicate_with_server(client_socket, session_key)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Client socket closed.")
        sys.stdout.flush()

def derive_session_key(shared_secret):
    """Derive a session key from the shared secret using PBKDF2."""
    salt = b"secure_salt"  # Use a fixed salt for simplicity (can be randomized)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit session key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_secret)

def decrypt_file_data(nonce, tag, ciphertext, session_key):
    print(f"[DEBUG] Decrypting chunk: Nonce={nonce.hex()}, Tag={tag.hex()}, Ciphertext={ciphertext.hex()[:64]}...")  # Log decryption details
    decryptor = Cipher(
        algorithms.AES(session_key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print(f"[DEBUG] Decrypted plaintext: {plaintext[:64]}...")  # Log the first 64 bytes of plaintext
    return plaintext

def communicate_with_server(client_socket, session_key):
    """Handle communication with the server using the session key."""
    while True:
        # Receive data until we have the full menu or a consent request
        data = b""
        while b"Choose an option:" not in data and b"(yes/no):" not in data:
            chunk = client_socket.recv(1024)
            if not chunk:
                print("Server disconnected.")
                sys.stdout.flush()
                return
            data += chunk

        # Decode the received data
        menu = data.decode('utf-8')
        print(menu, end='')

        # Handle consent requests
        if "(yes/no):" in menu:
            # Consent request received
            consent = input().strip().lower()  # Ask the user for consent
            client_socket.send(consent.encode('utf-8'))  # Send the response to the server
            continue  # Go back to waiting for the next server message

        # Get and send choice for the main menu
        choice = input().strip()
        client_socket.send(choice.encode('utf-8'))

        # Handle file request with consent (Option 2)
        if choice == "2":
            # Receive the list of files or prompt
            file_list = client_socket.recv(1024).decode('utf-8')
            print(file_list, end='')

            # Send file request
            requested_file = input().strip()
            client_socket.send(requested_file.encode('utf-8'))

            # Receive files
            downloads_dir = "downloads"  # Ensure the downloads directory exists
            if not os.path.exists(downloads_dir):
                os.makedirs(downloads_dir)

            while True:
                data = client_socket.recv(1024)
                if data.startswith(b"START"):
                    # Parse file name and size
                    _, file_name, _ = data.decode('utf-8').split(" ", 2)
                    print(f"Receiving file: {file_name}")
                    file_path = os.path.join(downloads_dir, file_name)  # Save in downloads folder
                    with open(file_path, "wb") as f:
                        while True:
                            chunk = client_socket.recv(1024)
                            if b"END_OF_FILE" in chunk:
                                chunk = chunk.replace(b"END_OF_FILE", b"")
                                break
                            # Extract nonce, tag, and ciphertext
                            nonce = chunk[:12]
                            tag = chunk[12:28]
                            ciphertext = chunk[28:]
                            plaintext = decrypt_file_data(nonce, tag, ciphertext, session_key)
                            f.write(plaintext)
                    print(f"File '{file_name}' received successfully in the 'downloads' folder.")
                elif data == b"END_OF_DOWNLOADS":
                    print("All requested files have been downloaded.")
                    break
                else:
                    print(data.decode('utf-8'), end='')

            # Exit the loop and return to the main menu
            print("\nReturning to the main menu...")

        # Handle file send with consent (Option 3)
        if choice == "3":
            file_list = client_socket.recv(1024).decode('utf-8')
            print(file_list, end='')

            selected_file = input().strip()
            client_socket.send(selected_file.encode('utf-8'))

            # Wait for consent response
            consent_response = client_socket.recv(1024).decode('utf-8')
            print(consent_response, end='')

            if "Consent granted" in consent_response:
                # Locate the file in the shared_files directory
                shared_dir = "shared_files"
                file_path = os.path.join(shared_dir, selected_file)

                try:
                    with open(file_path, "rb") as f:
                        file_size = os.path.getsize(file_path)
                        client_socket.send(f"START {selected_file} {file_size}".encode('utf-8'))
                        while chunk := f.read(1024):
                            client_socket.send(chunk)
                        client_socket.send(b"END_OF_FILE")
                        print(f"File '{selected_file}' sent successfully.")
                except FileNotFoundError:
                    print(f"\nFile '{selected_file}' not found in the 'shared_files' directory.")

        # Handle disconnect (Option 4)
        elif choice == "4":
            print("Disconnected from server.")
            break

        # Handle invalid options
        else:
            error_message = client_socket.recv(1024).decode('utf-8')
            print(error_message, end='')

def main():
    # Prompt for the user's name and register the peer first
    peer_name = input("\nEnter your name for discovery: ").strip()
    peer_port = random.randint(49152, 65535)  # Generate a random port in the dynamic/private range
    print(f"Assigned random port: {peer_port}")  # Inform the user of the assigned port

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
                server = SocketServer("192.168.40.5", peer_port)  # Use the same random port
                print(f"Starting server on port {peer_port}")  # Inform the user of the server port
                threading.Thread(target=server.start, daemon=True).start()  # Use daemon threads to ensure proper shutdown

            elif command == "list":
                list_files()

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
