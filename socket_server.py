import socket
import threading
import os
import sys
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptoUtils import generate_ecdh_keys, encrypt_file_data

class SocketServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Socket server started on {self.host}:{self.port}")
        sys.stdout.flush()

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
        salt = b"secure_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
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
                self.list_files_for_client(client_socket)
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
        shared_dir = "shared_files"

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
                file_size = os.path.getsize(file_path)
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
            print("\nIf you get 'Invalid command. Type 'help' for a list of commands.' type 'yes' and press enter and then type 'yes' again and press enter to make it work")
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
                file_size = os.path.getsize(file_path)
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
            print("\nIf you get 'Invalid command. Type 'help' for a list of commands.' type 'yes' and press enter and then type 'yes' again and press enter to make it work")
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
                    print(f"[DEBUG] Encrypting chunk: Nonce={nonce.hex()}, Tag={tag.hex()}, Ciphertext={ciphertext.hex()[:64]}...")
                    client_socket.send(nonce + tag + ciphertext)
                    print(f"[DEBUG] Sent encrypted chunk of size {len(ciphertext)} bytes")

            # Send the END_OF_FILE marker
            client_socket.send(b"END_OF_FILE")
            print(f"[DEBUG] Sent END_OF_FILE marker for file '{file_name}'")

            print(f"File '{file_name}' sent successfully with encryption.")
        except Exception as e:
            print(f"Error while sending file '{file_path}': {e}")
            client_socket.send(f"Error while sending file '{file_name}'.\n".encode('utf-8'))