# CISC468Project
CISC 468: P2P Secure File Sharing Application

## Python
- Make sure you have the latest version of Python installed.

## Required PIP Install
- pip install cryptography
- pip install zeroconf

## Change Socket Server IP
- Assuming you have a Windows OS, do "CTRL+S" and search "CMD". 
- Type in the terminal "ipconfig" and find the section "Wireless LAN adapter Wi-Fi". 
- You want to copy the IP under "IPv4 Address.
- Go to the "main.py" code and replace the IP in the line of code "server = SocketServer("192.168.40.5", peer_port)"
- Make sure to save.

## Workspace Folders
- The "shared_files" folder are your files that your peer can see to request to download.
- The "downloads" folder are the files you receive and get downloaded.

## Setting Up Terminals for Python to Python
1. **Terminal 1**: Start the server.
   - Run the following command:
     python3 main.py
   - Enter your name when prompted and you can type the available commands "list", "discover" and "quit"
   - In order to use "connect", you first have to start the socket server by typing "ss" and pressing Enter.

2. **Terminal 2**: Start a client to connect to the server.
   - Run the following command:
     python3 main.py
   - Enter your name when prompted and use the "connect" command to connect to the server.
   - You will need to enter the server's username to establish the connection.

## Things to keep in mind
- If the terminal ever freezes on the prompt, you will have to restart the program.
- If the consent is given to the receiving side, you will have to type "yes" then enter and then again type "yes" and enter. This is for both Request File (with consent) and Send File (with consent).
- After you entered the file you want to send or receive, you will have to switch to the other terminal and accept / decline. Reason I'm saying this is because you may think the terminal is frozen after you ask for a file name, but no you just have to switch terminals and accept / decline the file to be received or sent.