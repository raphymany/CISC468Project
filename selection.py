import sys

def show_help():
    print("""
Available commands:
    discover  - List available peers on the network
    connect   - Connect to a discovered peer
    contacts  - Check mutual authentication of contacts
    quit      - Exit the application
""")

def main():
    print("P2P Secure File Sharing Application")
    show_help()
    
    while True:
        command = input("Enter command: ").strip().lower()
        
        if command == "discover":
            print("[Feature 1] Discovering peers...")
            # Placeholder for peer discovery logic
        
        elif command == "connect":
            print("[Feature 2] Connecting to peer...")
            # Placeholder for connection logic
        
        elif command == "contacts":
            print("[Feature 3] Checking authenticated contacts...")
            # Placeholder for mutual authentication check
        
        elif command == "quit":
            print("Exiting application.")
            sys.exit(0)
        
        else:
            print("Invalid command. Type 'help' for a list of commands.")

if __name__ == "__main__":
    main()
