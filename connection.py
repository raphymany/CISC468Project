import socket
import os
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptoUtils import generate_ecdh_keys, derive_session_key, decrypt_file_data

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
        if len(server_public_key_der) < 90:
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
            consent = input().strip().lower()
            client_socket.send(consent.encode('utf-8'))
            continue

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
            downloads_dir = "downloads"
            if not os.path.exists(downloads_dir):
                os.makedirs(downloads_dir)

            while True:
                data = client_socket.recv(1024)
                if data.startswith(b"START"):
                    # Parse file name and size
                    _, file_name, _ = data.decode('utf-8').split(" ", 2)
                    print(f"Receiving file: {file_name}")
                    file_path = os.path.join(downloads_dir, file_name)
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